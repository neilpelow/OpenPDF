package org.openpdf.text.pdf.crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public interface ICryptoService {
    // --- Symmetric Encryption/Decryption ---
    byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException;
    byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException;

    // --- Asymmetric Encryption/Decryption (Public Key) ---
    byte[] encryptWithPublicKey(byte[] data, Certificate certificate) throws GeneralSecurityException;
    byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws GeneralSecurityException;

    // --- Hashing/Digest ---
    byte[] digest(byte[] data, String algorithm) throws GeneralSecurityException;

    // --- PKCS#7/CMS Signatures ---
    byte[] signPKCS7(byte[] data, PrivateKey privateKey, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException;
    boolean verifyPKCS7(byte[] data, byte[] signature, Certificate[] chain, String digestAlgorithm) throws GeneralSecurityException;

    // --- Certificate/CRL Handling ---
    void checkCertificateEncoding(Certificate certificate) throws GeneralSecurityException;

    // --- OCSP ---
    byte[] generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws GeneralSecurityException;
    boolean validateOCSPResponse(byte[] ocspResponse, X509Certificate issuerCert, X509Certificate cert) throws GeneralSecurityException;

    // --- TSA (Timestamp Authority) ---
    byte[] getTimeStampToken(byte[] imprint, String tsaUrl, String tsaUsername, String tsaPassword) throws GeneralSecurityException;

    // --- Envelope Handling (CMS/PKCS#7) ---
    byte[] createEnvelopedData(List<Certificate> recipients, byte[] data) throws GeneralSecurityException;
    byte[] extractEnvelopedData(byte[] envelopedData, PrivateKey privateKey, Certificate certificate) throws GeneralSecurityException;
} 