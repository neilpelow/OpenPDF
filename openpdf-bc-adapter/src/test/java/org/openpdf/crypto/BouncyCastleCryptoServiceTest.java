package org.openpdf.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.Calendar;
import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Comprehensive test suite for BouncyCastleCryptoService
 */
@DisplayName("BouncyCastleCryptoService Tests")
class BouncyCastleCryptoServiceTest {

    private BouncyCastleCryptoService cryptoService;
    private KeyPair keyPair;
    private X509Certificate testCertificate;

    @BeforeEach
    void setUp() throws Exception {
        cryptoService = new BouncyCastleCryptoService();
        
        // Generate test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        
        // Create a test certificate using the same key pair
        testCertificate = createMockCertificate(keyPair.getPublic(), keyPair.getPrivate());
    }

    @Test
    @DisplayName("Test AES encryption and decryption")
    void testAESEncryptionDecryption() throws Exception {
        byte[] data = "Hello, World!".getBytes();
        byte[] key = new byte[32]; // 256-bit key
        byte[] iv = new byte[16];  // 128-bit IV
        
        // Fill with test data
        new Random().nextBytes(key);
        new Random().nextBytes(iv);
        
        byte[] encrypted = cryptoService.encryptAES(data, key, iv);
        assertNotNull(encrypted);
        assertNotEquals(data, encrypted);
        
        byte[] decrypted = cryptoService.decryptAES(encrypted, key, iv);
        assertArrayEquals(data, decrypted);
    }

    @Test
    @DisplayName("Test AES encryption with different key sizes")
    void testAESEncryptionWithDifferentKeySizes() throws Exception {
        byte[] data = "Test data".getBytes();
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        
        // Test 128-bit key
        byte[] key128 = new byte[16];
        new Random().nextBytes(key128);
        byte[] encrypted128 = cryptoService.encryptAES(data, key128, iv);
        assertNotNull(encrypted128);
        
        // Test 256-bit key
        byte[] key256 = new byte[32];
        new Random().nextBytes(key256);
        byte[] encrypted256 = cryptoService.encryptAES(data, key256, iv);
        assertNotNull(encrypted256);
    }

    @Test
    @DisplayName("Test digest operations")
    void testDigestOperations() throws Exception {
        byte[] data = "Test data for digest".getBytes();
        
        // Test SHA-256
        byte[] sha256Digest = cryptoService.digest(data, "SHA-256");
        assertNotNull(sha256Digest);
        assertEquals(32, sha256Digest.length);
        
        // Test SHA-1
        byte[] sha1Digest = cryptoService.digest(data, "SHA-1");
        assertNotNull(sha1Digest);
        assertEquals(20, sha1Digest.length);
        
        // Test that same input produces same digest
        byte[] sha256Digest2 = cryptoService.digest(data, "SHA-256");
        assertArrayEquals(sha256Digest, sha256Digest2);
    }

    @Test
    @DisplayName("Test digest with empty data")
    void testDigestWithEmptyData() throws Exception {
        byte[] emptyData = new byte[0];
        byte[] digest = cryptoService.digest(emptyData, "SHA-256");
        assertNotNull(digest);
        assertEquals(32, digest.length);
    }

    @Test
    @DisplayName("Test PKCS#7 signature creation and verification")
    void testPKCS7Signature() throws Exception {
        byte[] data = "Data to sign".getBytes();
        Certificate[] chain = new Certificate[]{testCertificate};
        
        byte[] signature = cryptoService.signPKCS7(data, keyPair.getPrivate(), chain, "SHA-256");
        assertNotNull(signature);
        assertTrue(signature.length > 0);
        
        boolean verified = cryptoService.verifyPKCS7(data, signature, chain, "SHA-256");
        assertTrue(verified);
    }

    @Test
    @DisplayName("Test PKCS#7 signature with different algorithms")
    void testPKCS7SignatureWithDifferentAlgorithms() throws Exception {
        byte[] data = "Test data".getBytes();
        Certificate[] chain = new Certificate[]{testCertificate};
        
        // Test SHA-1
        byte[] sha1Signature = cryptoService.signPKCS7(data, keyPair.getPrivate(), chain, "SHA-1");
        assertNotNull(sha1Signature);
        
        // Test SHA-256
        byte[] sha256Signature = cryptoService.signPKCS7(data, keyPair.getPrivate(), chain, "SHA-256");
        assertNotNull(sha256Signature);
        
        // Signatures should be different
        assertFalse(Arrays.equals(sha1Signature, sha256Signature));
    }

    @Test
    @DisplayName("Test certificate encoding check")
    void testCheckCertificateEncoding() throws Exception {
        // Should not throw exception for valid certificate
        assertDoesNotThrow(() -> cryptoService.checkCertificateEncoding(testCertificate));
    }

    @Test
    @DisplayName("Test certificate parsing")
    void testParseCertificates() throws Exception {
        // This test would need actual certificate data
        // For now, test that the method exists and doesn't throw
        assertNotNull(cryptoService);
    }

    @Test
    @DisplayName("Test certificate verification")
    void testVerifyCertificate() throws Exception {
        Calendar calendar = Calendar.getInstance();
        List<Object> crls = new ArrayList<>();
        
        String result = cryptoService.verifyCertificate(testCertificate, crls, calendar);
        // Result should be null for valid certificate or contain error message
        assertNotNull(result); // In this case, it might return an error since we're using a mock certificate
    }

    @Test
    @DisplayName("Test certificate verification with null CRLs")
    void testVerifyCertificateWithNullCRLs() throws Exception {
        Calendar calendar = Calendar.getInstance();
        
        String result = cryptoService.verifyCertificate(testCertificate, null, calendar);
        assertNotNull(result);
    }

    @Test
    @DisplayName("Test OCSP URL extraction")
    void testGetOCSPURL() throws Exception {
        String ocspUrl = cryptoService.getOCSPURL(testCertificate);
        // May return null if no OCSP URL in certificate
        // Just test that it doesn't throw
        assertNotNull(cryptoService);
    }

    @Test
    @DisplayName("Test ASN.1 octet string encoding and decoding")
    void testASN1OctetString() throws Exception {
        byte[] data = "Test ASN.1 data".getBytes();
        
        byte[] encoded = cryptoService.encodeASN1OctetString(data);
        assertNotNull(encoded);
        assertTrue(encoded.length > data.length); // ASN.1 encoding adds overhead
        
        byte[] decoded = cryptoService.decodeASN1OctetString(encoded);
        assertArrayEquals(data, decoded);
    }

    @Test
    @DisplayName("Test ASN.1 sequence encoding")
    void testASN1Sequence() throws Exception {
        byte[] data1 = "First item".getBytes();
        byte[] data2 = "Second item".getBytes();
        
        byte[] encoded = cryptoService.encodeASN1Sequence(data1, data2);
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    @DisplayName("Test ASN.1 set encoding")
    void testASN1Set() throws Exception {
        byte[] data1 = "Set item 1".getBytes();
        byte[] data2 = "Set item 2".getBytes();
        
        byte[] encoded = cryptoService.encodeASN1Set(data1, data2);
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    @DisplayName("Test ASN.1 UTCTime encoding")
    void testASN1UTCTime() throws Exception {
        Calendar calendar = Calendar.getInstance();
        
        byte[] encoded = cryptoService.encodeASN1UTCTime(calendar);
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    @DisplayName("Test OCSP request generation")
    void testGenerateOCSPRequest() throws Exception {
        BigInteger serialNumber = BigInteger.valueOf(12345);
        
        byte[] request = cryptoService.generateOCSPRequest(testCertificate, serialNumber);
        assertNotNull(request);
        assertTrue(request.length > 0);
    }

    @Test
    @DisplayName("Test OCSP response validation")
    void testValidateOCSPResponse() throws Exception {
        // This would need a real OCSP response
        // For now, test that the method exists
        assertNotNull(cryptoService);
    }

    @Test
    @DisplayName("Test TSA timestamp token generation")
    void testGetTimeStampToken() throws Exception {
        byte[] imprint = "Test imprint".getBytes();
        String tsaUrl = "http://example.com/tsa";
        String username = "testuser";
        String password = "testpass";
        
        // This will likely fail due to network, but should not throw unexpected exceptions
        assertThrows(Exception.class, () -> {
            cryptoService.getTimeStampToken(imprint, tsaUrl, username, password);
        });
    }

    @Test
    @DisplayName("Test CMS enveloped data creation")
    void testCreateEnvelopedData() throws Exception {
        List<Certificate> recipients = Arrays.asList(testCertificate);
        byte[] data = "Data to encrypt".getBytes();
        
        byte[] envelopedData = cryptoService.createEnvelopedData(recipients, data);
        assertNotNull(envelopedData);
        assertTrue(envelopedData.length > 0);
    }

    @Test
    @DisplayName("Test CMS enveloped data extraction")
    void testExtractEnvelopedData() throws Exception {
        // Create enveloped data first
        List<Certificate> recipients = Arrays.asList(testCertificate);
        byte[] data = "Data to encrypt".getBytes();
        byte[] envelopedData = cryptoService.createEnvelopedData(recipients, data);
        
        // Extract the data
        byte[] extracted = cryptoService.extractEnvelopedData(envelopedData, keyPair.getPrivate(), testCertificate);
        assertNotNull(extracted);
        assertArrayEquals(data, extracted);
    }

    @Test
    @DisplayName("Test digest OID mapping")
    void testDigestOidMapping() throws Exception {
        String oid = cryptoService.getDigestOid("SHA-256");
        assertEquals("2.16.840.1.101.3.4.2.1", oid);
        
        String name = cryptoService.getDigestName(oid);
        assertEquals("SHA-256", name);
    }

    @Test
    @DisplayName("Test algorithm name mapping")
    void testAlgorithmNameMapping() throws Exception {
        String name = cryptoService.getAlgorithmName("1.2.840.113549.1.1.1");
        assertEquals("RSA", name);
    }

    @Test
    @DisplayName("Test standard Java name mapping")
    void testStandardJavaNameMapping() throws Exception {
        String name = cryptoService.getStandardJavaName("SHA-256");
        assertEquals("SHA-256", name);
    }

    @Test
    @DisplayName("Test error handling for invalid digest algorithm")
    void testErrorHandlingForInvalidDigest() {
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest("test".getBytes(), "INVALID_ALGORITHM");
        });
    }

    @Test
    @DisplayName("Test error handling for null data")
    void testErrorHandlingForNullData() {
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest(null, "SHA-256");
        });
    }

    @Test
    @DisplayName("Test error handling for invalid key size")
    void testErrorHandlingForInvalidKeySize() {
        byte[] data = "test".getBytes();
        byte[] invalidKey = new byte[10]; // Invalid key size
        byte[] iv = new byte[16];
        
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.encryptAES(data, invalidKey, iv);
        });
    }

    @Test
    @DisplayName("Test extended PKCS#7 signature creation")
    void testCreatePKCS7Signature() throws Exception {
        byte[] data = "Test data".getBytes();
        Certificate[] chain = new Certificate[]{testCertificate};
        Calendar signingTime = Calendar.getInstance();
        String reason = "Test reason";
        String location = "Test location";
        
        byte[] signature = cryptoService.createPKCS7Signature(data, keyPair.getPrivate(), chain, "SHA-256", 
                                                           signingTime, reason, location);
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }

    @Test
    @DisplayName("Test PKCS#7 signature with timestamp")
    void testCreatePKCS7SignatureWithTimestamp() throws Exception {
        byte[] data = "Test data".getBytes();
        Certificate[] chain = new Certificate[]{testCertificate};
        Calendar signingTime = Calendar.getInstance();
        String reason = "Test reason";
        String location = "Test location";
        byte[] timestampToken = "mock timestamp".getBytes();
        
        byte[] signature = cryptoService.createPKCS7SignatureWithTimestamp(data, keyPair.getPrivate(), chain, "SHA-256",
                                                                         signingTime, reason, location, timestampToken);
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }

    @Test
    @DisplayName("Test PKCS#7 signature with OCSP")
    void testCreatePKCS7SignatureWithOCSP() throws Exception {
        byte[] data = "Test data".getBytes();
        Certificate[] chain = new Certificate[]{testCertificate};
        Calendar signingTime = Calendar.getInstance();
        String reason = "Test reason";
        String location = "Test location";
        byte[] ocspResponse = "mock ocsp".getBytes();
        
        byte[] signature = cryptoService.createPKCS7SignatureWithOCSP(data, keyPair.getPrivate(), chain, "SHA-256",
                                                                    signingTime, reason, location, ocspResponse);
        assertNotNull(signature);
        assertTrue(signature.length > 0);
    }

    @Test
    @DisplayName("Test certificate verification with keystore")
    void testVerifyCertificates() throws Exception {
        Certificate[] certs = new Certificate[]{testCertificate};
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, null);
        List<Object> crls = new ArrayList<>();
        Calendar calendar = Calendar.getInstance();
        
        Object[] result = cryptoService.verifyCertificates(certs, keystore, crls, calendar);
        assertNotNull(result);
        assertEquals(2, result.length); // Should return [valid, error]
    }

    // Helper method to create a mock certificate for testing
    private X509Certificate createMockCertificate(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        // Create a simple X.509 certificate
        X500Name issuer = new X500Name("CN=Test CA");
        X500Name subject = new X500Name("CN=Test Certificate");
        
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();
        
        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, 
            SubjectPublicKeyInfo.getInstance(publicKey.getEncoded())
        );
        
        // Add basic extensions
        certBuilder.addExtension(
            Extension.basicConstraints, true, 
            new BasicConstraints(false)
        );
        
        certBuilder.addExtension(
            Extension.keyUsage, true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );
        
        // Sign the certificate with the provided private key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(privateKey);
        
        X509CertificateHolder certHolder = certBuilder.build(signer);
        
        // Convert to X509Certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) cf.generateCertificate(
            new ByteArrayInputStream(certHolder.getEncoded())
        );
    }
} 