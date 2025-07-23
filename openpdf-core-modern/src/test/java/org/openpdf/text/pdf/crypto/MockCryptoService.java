package org.openpdf.text.pdf.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

/**
 * Mock implementation of ICryptoService for testing purposes.
 * This provides basic functionality without requiring the actual adapter modules.
 */
public class MockCryptoService implements ICryptoService {
    
    // --- Symmetric Encryption/Decryption ---
    @Override
    public byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    // --- Asymmetric Encryption/Decryption (Public Key) ---
    @Override
    public byte[] encryptWithPublicKey(byte[] data, Certificate certificate) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    // --- Hashing/Digest ---
    @Override
    public byte[] digest(byte[] data, String algorithm) throws GeneralSecurityException {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return digest.digest(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to compute digest", e);
        }
    }
    
    // --- PKCS#7/CMS Signatures ---
    @Override
    public byte[] signPKCS7(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public boolean verifyPKCS7(byte[] data, byte[] signature, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException {
        // Mock implementation - always return true
        return true;
    }
    
    // --- Extended PKCS#7/CMS Methods ---
    @Override
    public byte[] createPKCS7Signature(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm, 
                                     Calendar signingTime, String reason, String location) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public byte[] createPKCS7SignatureWithTimestamp(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm,
                                                  Calendar signingTime, String reason, String location, byte[] timestampToken) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public byte[] createPKCS7SignatureWithOCSP(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm,
                                             Calendar signingTime, String reason, String location, byte[] ocspResponse) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    // --- Certificate/CRL Handling ---
    @Override
    public void checkCertificateEncoding(Certificate certificate) throws GeneralSecurityException {
        // Mock implementation - do nothing
    }
    
    @Override
    public Certificate[] parseCertificates(byte[] certData) throws GeneralSecurityException {
        // Mock implementation - return empty array
        return new Certificate[0];
    }
    
    @Override
    public String verifyCertificate(X509Certificate cert, List<Object> crls, Calendar calendar) throws GeneralSecurityException {
        // Mock implementation - return success
        return "Valid";
    }
    
    @Override
    public Object[] verifyCertificates(Certificate[] certs, KeyStore keystore, List<Object> crls, Calendar calendar) throws GeneralSecurityException {
        // Mock implementation - return empty array
        return new Object[0];
    }
    
    @Override
    public String getOCSPURL(X509Certificate certificate) throws GeneralSecurityException {
        // Mock implementation - return null
        return null;
    }
    
    // --- ASN.1 Operations ---
    @Override
    public byte[] encodeASN1OctetString(byte[] data) throws GeneralSecurityException {
        // Mock implementation - return data as-is
        return data;
    }
    
    @Override
    public byte[] decodeASN1OctetString(byte[] asn1Data) throws GeneralSecurityException {
        // Mock implementation - return data as-is
        return asn1Data;
    }
    
    @Override
    public byte[] encodeASN1Sequence(byte[]... data) throws GeneralSecurityException {
        // Mock implementation - concatenate all data
        int totalLength = 0;
        for (byte[] d : data) {
            totalLength += d.length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] d : data) {
            System.arraycopy(d, 0, result, offset, d.length);
            offset += d.length;
        }
        return result;
    }
    
    @Override
    public byte[] encodeASN1Set(byte[]... data) throws GeneralSecurityException {
        // Mock implementation - same as sequence
        return encodeASN1Sequence(data);
    }
    
    @Override
    public byte[] encodeASN1UTCTime(Calendar time) throws GeneralSecurityException {
        // Mock implementation - return empty array
        return new byte[0];
    }
    
    // --- OCSP ---
    @Override
    public byte[] generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws GeneralSecurityException {
        // Mock implementation - return empty array
        return new byte[0];
    }
    
    @Override
    public boolean validateOCSPResponse(byte[] ocspResponse, X509Certificate issuerCert, X509Certificate cert) throws GeneralSecurityException {
        // Mock implementation - always return true
        return true;
    }
    
    // --- TSA (Timestamp Authority) ---
    @Override
    public byte[] getTimeStampToken(byte[] imprint, String tsaUrl, String tsaUsername, String tsaPassword) throws GeneralSecurityException {
        // Mock implementation - return empty array
        return new byte[0];
    }
    
    // --- Envelope Handling (CMS/PKCS#7) ---
    @Override
    public byte[] createEnvelopedData(List<Certificate> recipients, byte[] data) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return data;
    }
    
    @Override
    public byte[] extractEnvelopedData(byte[] envelopedData, PrivateKey privateKey, Certificate certificate) throws GeneralSecurityException {
        // Mock implementation - just return the data as-is
        return envelopedData;
    }
    
    // --- Utility Methods ---
    @Override
    public String getDigestOid(String digestName) throws GeneralSecurityException {
        // Mock implementation - return common mappings
        switch (digestName.toUpperCase()) {
            case "MD5": return "1.2.840.113549.2.5";
            case "SHA-1": return "1.3.14.3.2.26";
            case "SHA-256": return "2.16.840.1.101.3.4.2.1";
            case "SHA-512": return "2.16.840.1.101.3.4.2.3";
            default: return digestName;
        }
    }
    
    @Override
    public String getDigestName(String oid) throws GeneralSecurityException {
        // Mock implementation - return common mappings
        switch (oid) {
            case "1.2.840.113549.2.5": return "MD5";
            case "1.3.14.3.2.26": return "SHA-1";
            case "2.16.840.1.101.3.4.2.1": return "SHA-256";
            case "2.16.840.1.101.3.4.2.3": return "SHA-512";
            default: return oid;
        }
    }
    
    @Override
    public String getAlgorithmName(String oid) throws GeneralSecurityException {
        // Mock implementation - return common mappings
        switch (oid) {
            case "1.2.840.113549.2.5": return "MD5";
            case "1.3.14.3.2.26": return "SHA-1";
            case "2.16.840.1.101.3.4.2.1": return "SHA-256";
            case "2.16.840.1.101.3.4.2.3": return "SHA-512";
            case "1.2.840.113549.1.1.1": return "RSA";
            default: return oid;
        }
    }
    
    @Override
    public String getStandardJavaName(String algName) throws GeneralSecurityException {
        // Mock implementation - return as-is
        return algName;
    }
} 