package org.openpdf.crypto;

import org.openpdf.text.pdf.crypto.ICryptoService;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;
import java.util.Base64;
import java.io.*;
import java.net.*;
import java.util.Collection;
import java.util.ArrayList;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class FipsBouncyCastleCryptoService implements ICryptoService {

    static {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Override
    public byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        try {
            BlockCipher aes = new AESEngine();
            BlockCipher cbc = new CBCBlockCipher(aes);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc);
            KeyParameter kp = new KeyParameter(key);
            ParametersWithIV piv = new ParametersWithIV(kp, iv);
            cipher.init(true, piv);
            
            byte[] output = new byte[cipher.getOutputSize(data.length)];
            int len = cipher.processBytes(data, 0, data.length, output, 0);
            len += cipher.doFinal(output, len);
            
            byte[] result = new byte[len];
            System.arraycopy(output, 0, result, 0, len);
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("AES encryption failed", e);
        }
    }

    @Override
    public byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        try {
            BlockCipher aes = new AESEngine();
            BlockCipher cbc = new CBCBlockCipher(aes);
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc);
            KeyParameter kp = new KeyParameter(key);
            ParametersWithIV piv = new ParametersWithIV(kp, iv);
            cipher.init(false, piv);
            
            byte[] output = new byte[cipher.getOutputSize(data.length)];
            int len = cipher.processBytes(data, 0, data.length, output, 0);
            len += cipher.doFinal(output, len);
            
            byte[] result = new byte[len];
            System.arraycopy(output, 0, result, 0, len);
            return result;
        } catch (Exception e) {
            throw new GeneralSecurityException("AES decryption failed", e);
        }
    }

    @Override
    public byte[] encryptWithPublicKey(byte[] data, Certificate certificate) throws GeneralSecurityException {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding", "BCFIPS");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, certificate.getPublicKey());
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Public key encryption failed", e);
        }
    }

    @Override
    public byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding", "BCFIPS");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Private key decryption failed", e);
        }
    }

    @Override
    public byte[] digest(byte[] data, String algorithm) throws GeneralSecurityException {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm, "BCFIPS");
            return md.digest(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Digest calculation failed", e);
        }
    }

    @Override
    public byte[] signPKCS7(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException {
        try {
            MessageDigest md = MessageDigest.getInstance(digestAlgorithm, "BCFIPS");
            byte[] digest = md.digest(data);
            
            java.security.Signature sig = java.security.Signature.getInstance(digestAlgorithm + "withRSA", "BCFIPS");
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new GeneralSecurityException("PKCS#7 signing failed", e);
        }
    }

    @Override
    public boolean verifyPKCS7(byte[] data, byte[] signature, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException {
        try {
            java.security.Signature sig = java.security.Signature.getInstance(digestAlgorithm + "withRSA", "BCFIPS");
            sig.initVerify(chain[0].getPublicKey());
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            throw new GeneralSecurityException("PKCS#7 verification failed", e);
        }
    }

    @Override
    public void checkCertificateEncoding(Certificate certificate) throws GeneralSecurityException {
        try {
            new X509CertificateHolder(certificate.getEncoded());
        } catch (Exception e) {
            throw new GeneralSecurityException("Certificate encoding check failed", e);
        }
    }

    @Override
    public byte[] generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws GeneralSecurityException {
        try {
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BCFIPS").build();
            
            CertificateID id = new CertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert), serialNumber);
            
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(id);
            
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            byte[] nonce = new byte[16];
            new Random().nextBytes(nonce);
            extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce));
            gen.setRequestExtensions(extGen.generate());
            
            return gen.build().getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("OCSP request generation failed", e);
        }
    }

    @Override
    public boolean validateOCSPResponse(byte[] ocspResponse, X509Certificate issuerCert, X509Certificate cert) throws GeneralSecurityException {
        try {
            OCSPResp response = new OCSPResp(ocspResponse);
            BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
            
            SingleResp[] responses = basicResp.getResponses();
            if (responses.length == 1) {
                SingleResp resp = responses[0];
                Object status = resp.getCertStatus();
                return status == null; // null means good status
            }
            return false;
        } catch (Exception e) {
            throw new GeneralSecurityException("OCSP response validation failed", e);
        }
    }

    @Override
    public byte[] getTimeStampToken(byte[] imprint, String tsaUrl, String tsaUsername, String tsaPassword) throws GeneralSecurityException {
        try {
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.setCertReq(true);
            
            BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
            ASN1ObjectIdentifier digestOid = X509ObjectIdentifiers.id_SHA1;
            
            TimeStampRequest request = tsqGenerator.generate(digestOid, imprint, nonce);
            byte[] requestBytes = request.getEncoded();
            byte[] responseBytes = sendTSARequest(tsaUrl, requestBytes, tsaUsername, tsaPassword);
            
            TimeStampResponse response = new TimeStampResponse(responseBytes);
            response.validate(request);
            
            TimeStampToken tsToken = response.getTimeStampToken();
            if (tsToken == null) {
                throw new GeneralSecurityException("TSA failed to return timestamp token");
            }
            
            return tsToken.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("Timestamp token generation failed", e);
        }
    }

    @Override
    public byte[] createEnvelopedData(List<Certificate> recipients, byte[] data) throws GeneralSecurityException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BCFIPS");
            keyGen.init(256);
            SecretKey contentEncryptionKey = keyGen.generateKey();
            
            CMSEnvelopedDataGenerator envelopedDataGen = new CMSEnvelopedDataGenerator();
            
            for (Certificate recipient : recipients) {
                if (recipient instanceof X509Certificate) {
                    envelopedDataGen.addRecipientInfoGenerator(
                        new JceKeyTransRecipientInfoGenerator((X509Certificate) recipient)
                            .setProvider("BCFIPS"));
                }
            }
            
            CMSEnvelopedData envelopedData = envelopedDataGen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                    .setProvider("BCFIPS")
                    .build(contentEncryptionKey));
            
            return envelopedData.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("Envelope creation failed", e);
        }
    }

    @Override
    public byte[] extractEnvelopedData(byte[] envelopedData, PrivateKey privateKey, Certificate certificate) throws GeneralSecurityException {
        try {
            CMSEnvelopedData data = new CMSEnvelopedData(envelopedData);
            Collection<RecipientInformation> recipientInformations = data.getRecipientInfos().getRecipients();
            
            for (RecipientInformation recipientInfo : recipientInformations) {
                if (recipientInfo.getRID().match(certificate)) {
                    Recipient rec = new JceKeyTransEnvelopedRecipient(privateKey);
                    return recipientInfo.getContent(rec);
                }
            }
            return null;
        } catch (Exception e) {
            throw new GeneralSecurityException("Envelope extraction failed", e);
        }
    }

    private byte[] sendTSARequest(String tsaUrl, byte[] requestBytes, String tsaUsername, String tsaPassword) throws Exception {
        URL url = new URL(tsaUrl);
        URLConnection connection = url.openConnection();
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setUseCaches(false);
        connection.setRequestProperty("Content-Type", "application/timestamp-query");
        connection.setRequestProperty("Content-Transfer-Encoding", "binary");
        
        if (tsaUsername != null && tsaPassword != null) {
            String userPassword = tsaUsername + ":" + tsaPassword;
            connection.setRequestProperty("Authorization", "Basic " + 
                    Base64.getEncoder().encodeToString(userPassword.getBytes()));
        }
        
        try (OutputStream out = connection.getOutputStream()) {
            out.write(requestBytes);
        }
        
        try (InputStream in = connection.getInputStream()) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) >= 0) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        }
    }
} 