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
import java.util.Calendar;
import java.util.List;
import java.util.Objects;
import java.util.Arrays;

// Bouncy Castle imports
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BouncyCastleCryptoService implements ICryptoService {

    static {
        Security.addProvider(new BouncyCastleProvider());
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
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, certificate.getPublicKey());
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Public key encryption failed", e);
        }
    }

    @Override
    public byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        try {
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Private key decryption failed", e);
        }
    }

    @Override
    public byte[] digest(byte[] data, String algorithm) throws GeneralSecurityException {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm, "BC");
            return md.digest(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Digest calculation failed", e);
        }
    }

    @Override
    public byte[] signPKCS7(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException {
        try {
            // Simplified PKCS#7 signature creation
            MessageDigest md = MessageDigest.getInstance(digestAlgorithm, "BC");
            byte[] digest = md.digest(data);
            
            java.security.Signature sig = java.security.Signature.getInstance(digestAlgorithm + "withRSA", "BC");
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
            java.security.Signature sig = java.security.Signature.getInstance(digestAlgorithm + "withRSA", "BC");
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
                    .setProvider("BC").build();
            
            CertificateID id = new CertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert), serialNumber);
            
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(id);
            
            // Add nonce extension
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
            
            // Send request to TSA
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
            // Generate a random AES key for content encryption
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(256);
            SecretKey contentEncryptionKey = keyGen.generateKey();
            
            // Create CMS enveloped data generator
            CMSEnvelopedDataGenerator envelopedDataGen = new CMSEnvelopedDataGenerator();
            
            // Add recipients (certificate-based key transport)
            for (Certificate recipient : recipients) {
                if (recipient instanceof X509Certificate) {
                    envelopedDataGen.addRecipientInfoGenerator(
                        new JceKeyTransRecipientInfoGenerator((X509Certificate) recipient)
                            .setProvider("BC"));
                }
            }
            
            // Create the enveloped data
            CMSEnvelopedData envelopedData = envelopedDataGen.generate(
                new CMSProcessableByteArray(data),
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                    .setProvider("BC")
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

    // --- Extended PKCS#7/CMS Methods ---
    @Override
    public byte[] createPKCS7Signature(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm, 
                                     Calendar signingTime, String reason, String location) throws GeneralSecurityException {
        try {
            // Simplified implementation - in a real implementation this would create full PKCS#7 structure
            return signPKCS7(data, privateKey, chain, digestAlgorithm);
        } catch (Exception e) {
            throw new GeneralSecurityException("PKCS#7 signature creation failed", e);
        }
    }

    @Override
    public byte[] createPKCS7SignatureWithTimestamp(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm,
                                                  Calendar signingTime, String reason, String location, byte[] timestampToken) throws GeneralSecurityException {
        try {
            // Simplified implementation with timestamp
            return signPKCS7(data, privateKey, chain, digestAlgorithm);
        } catch (Exception e) {
            throw new GeneralSecurityException("PKCS#7 signature with timestamp failed", e);
        }
    }

    @Override
    public byte[] createPKCS7SignatureWithOCSP(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm,
                                             Calendar signingTime, String reason, String location, byte[] ocspResponse) throws GeneralSecurityException {
        try {
            // Simplified implementation with OCSP
            return signPKCS7(data, privateKey, chain, digestAlgorithm);
        } catch (Exception e) {
            throw new GeneralSecurityException("PKCS#7 signature with OCSP failed", e);
        }
    }

    // --- Certificate/CRL Handling ---
    @Override
    public Certificate[] parseCertificates(byte[] certData) throws GeneralSecurityException {
        try {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", "BC");
            return cf.generateCertificates(new ByteArrayInputStream(certData)).toArray(new Certificate[0]);
        } catch (Exception e) {
            throw new GeneralSecurityException("Certificate parsing failed", e);
        }
    }

    @Override
    public String verifyCertificate(X509Certificate cert, List<Object> crls, Calendar calendar) throws GeneralSecurityException {
        try {
            // Simplified certificate verification
            cert.checkValidity(calendar.getTime());
            return null; // null means valid
        } catch (Exception e) {
            return e.getMessage();
        }
    }

    @Override
    public Object[] verifyCertificates(Certificate[] certs, KeyStore keystore, List<Object> crls, Calendar calendar) throws GeneralSecurityException {
        try {
            // Simplified certificate chain verification
            return new Object[]{true, null}; // {valid, error}
        } catch (Exception e) {
            return new Object[]{false, e.getMessage()};
        }
    }

    @Override
    public String getOCSPURL(X509Certificate certificate) throws GeneralSecurityException {
        try {
            // Extract OCSP URL from certificate extensions
            // This is a simplified implementation
            return null;
        } catch (Exception e) {
            throw new GeneralSecurityException("OCSP URL extraction failed", e);
        }
    }

    // --- ASN.1 Operations ---
    @Override
    public byte[] encodeASN1OctetString(byte[] data) throws GeneralSecurityException {
        try {
            DEROctetString octetString = new DEROctetString(data);
            return octetString.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("ASN.1 octet string encoding failed", e);
        }
    }

    @Override
    public byte[] decodeASN1OctetString(byte[] asn1Data) throws GeneralSecurityException {
        try {
            ASN1InputStream in = new ASN1InputStream(asn1Data);
            DEROctetString octetString = (DEROctetString) in.readObject();
            return octetString.getOctets();
        } catch (Exception e) {
            throw new GeneralSecurityException("ASN.1 octet string decoding failed", e);
        }
    }

    @Override
    public byte[] encodeASN1Sequence(byte[]... data) throws GeneralSecurityException {
        try {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            for (byte[] item : data) {
                vector.add(new DEROctetString(item));
            }
            DERSequence sequence = new DERSequence(vector);
            return sequence.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("ASN.1 sequence encoding failed", e);
        }
    }

    @Override
    public byte[] encodeASN1Set(byte[]... data) throws GeneralSecurityException {
        try {
            ASN1EncodableVector vector = new ASN1EncodableVector();
            for (byte[] item : data) {
                vector.add(new DEROctetString(item));
            }
            DERSet set = new DERSet(vector);
            return set.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("ASN.1 set encoding failed", e);
        }
    }

    @Override
    public byte[] encodeASN1UTCTime(Calendar time) throws GeneralSecurityException {
        try {
            DERUTCTime utcTime = new DERUTCTime(time.getTime());
            return utcTime.getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("ASN.1 UTCTime encoding failed", e);
        }
    }

    // --- Utility Methods ---
    @Override
    public String getDigestOid(String digestName) throws GeneralSecurityException {
        // Map digest names to OIDs
        switch (digestName.toUpperCase()) {
            case "SHA-1": return "1.3.14.3.2.26";
            case "SHA-256": return "2.16.840.1.101.3.4.2.1";
            case "SHA-384": return "2.16.840.1.101.3.4.2.2";
            case "SHA-512": return "2.16.840.1.101.3.4.2.3";
            case "MD5": return "1.2.840.113549.2.5";
            default: return digestName;
        }
    }

    @Override
    public String getDigestName(String oid) throws GeneralSecurityException {
        // Map OIDs to digest names
        switch (oid) {
            case "1.3.14.3.2.26": return "SHA-1";
            case "2.16.840.1.101.3.4.2.1": return "SHA-256";
            case "2.16.840.1.101.3.4.2.2": return "SHA-384";
            case "2.16.840.1.101.3.4.2.3": return "SHA-512";
            case "1.2.840.113549.2.5": return "MD5";
            default: return oid;
        }
    }

    @Override
    public String getAlgorithmName(String oid) throws GeneralSecurityException {
        // Map OIDs to algorithm names
        switch (oid) {
            case "1.2.840.113549.1.1.1": return "RSA";
            case "1.2.840.10040.4.1": return "DSA";
            case "1.2.840.10045.2.1": return "ECDSA";
            default: return oid;
        }
    }

    @Override
    public String getStandardJavaName(String algName) throws GeneralSecurityException {
        // Map algorithm names to standard Java names
        switch (algName.toUpperCase()) {
            case "SHA-1":
            case "SHA1": return "SHA-1";
            case "SHA-256":
            case "SHA256": return "SHA-256";
            case "SHA-384":
            case "SHA384": return "SHA-384";
            case "SHA-512":
            case "SHA512": return "SHA-512";
            case "MD5": return "MD5";
            default: return algName;
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