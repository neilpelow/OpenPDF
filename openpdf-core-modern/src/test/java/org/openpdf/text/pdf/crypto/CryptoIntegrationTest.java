package org.openpdf.text.pdf.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import org.openpdf.text.Document;
import org.openpdf.text.Paragraph;
import org.openpdf.text.pdf.PdfWriter;
import org.openpdf.text.pdf.PdfReader;
import org.openpdf.text.pdf.PdfStamper;
import org.openpdf.text.pdf.PdfSignatureAppearance;
import org.openpdf.text.pdf.PdfDictionary;
import org.openpdf.text.pdf.PdfName;
import org.openpdf.text.pdf.PdfString;
import org.openpdf.text.pdf.PdfDate;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * End-to-end integration tests for cryptographic operations
 */
@DisplayName("Crypto Integration Tests")
class CryptoIntegrationTest {

    private ICryptoService cryptoService;
    private KeyPair keyPair;
    private X509Certificate testCertificate;

    @BeforeEach
    void setUp() throws Exception {
        cryptoService = CryptoServiceProvider.get();
        
        // Generate test key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
        
        // Create a mock certificate for testing
        testCertificate = createMockCertificate(keyPair.getPublic());
    }

    @Test
    @DisplayName("Test PDF creation with encryption")
    void testPdfCreationWithEncryption() throws Exception {
        // Create a simple PDF document
        Document document = new Document();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        PdfWriter writer = PdfWriter.getInstance(document, baos);
        
        // Set encryption using AES-128
        writer.setEncryption("userpass".getBytes(), "ownerpass".getBytes(), 
                           PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_128);
        
        document.open();
        document.add(new Paragraph("Test PDF with encryption"));
        document.close();
        
        byte[] pdfBytes = baos.toByteArray();
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 0);
        
        // Verify the PDF can be read with the correct password
        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes), "userpass".getBytes())) {
            assertTrue(reader.isEncrypted(), "PDF should be encrypted");
            assertEquals(1, reader.getNumberOfPages(), "PDF should have 1 page");
        }
    }

    @Test
    @DisplayName("Test PDF creation with AES-256 encryption")
    void testPdfCreationWithAES256Encryption() throws Exception {
        // Create a simple PDF document
        Document document = new Document();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        PdfWriter writer = PdfWriter.getInstance(document, baos);
        
        // Set encryption using AES-256
        writer.setEncryption("userpass".getBytes(), "ownerpass".getBytes(), 
                           PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_256_V3);
        
        document.open();
        document.add(new Paragraph("Test PDF with AES-256 encryption"));
        document.close();
        
        byte[] pdfBytes = baos.toByteArray();
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 0);
        
        // Verify the PDF can be read with the correct password
        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes), "userpass".getBytes())) {
            assertTrue(reader.isEncrypted(), "PDF should be encrypted");
            assertEquals(1, reader.getNumberOfPages(), "PDF should have 1 page");
        }
    }

    @Test
    @DisplayName("Test PDF signing with cryptographic service")
    void testPdfSigning() throws Exception {
        // Create a simple PDF document
        Document document = new Document();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        PdfWriter writer = PdfWriter.getInstance(document, baos);
        document.open();
        document.add(new Paragraph("Test PDF for signing"));
        document.close();
        
        byte[] pdfBytes = baos.toByteArray();
        
        // Create a signed PDF
        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
             ByteArrayOutputStream signedBaos = new ByteArrayOutputStream()) {
            
            PdfStamper stamper = PdfStamper.createSignature(reader, signedBaos, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            
            // Set signature appearance
            appearance.setReason("Test signature");
            appearance.setLocation("Test location");
            
            // Create signature dictionary
            PdfDictionary dic = new PdfDictionary();
            dic.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE);
            dic.put(PdfName.M, new PdfDate(Calendar.getInstance()));
            
            appearance.setCryptoDictionary(dic);
            appearance.setCertificationLevel(2);
            
            // Pre-close the signature
            Map<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, 8192); // Reserve space for signature
            appearance.preClose(exc);
            
            // Get the range to sign
            byte[] range = appearance.getRangeStream().readAllBytes();
            
            // Create signature using crypto service
            Certificate[] chain = new Certificate[]{testCertificate};
            byte[] signature = cryptoService.signPKCS7(range, keyPair.getPrivate(), chain, "SHA-256");
            
            // Close the signature
            PdfDictionary update = new PdfDictionary();
            update.put(PdfName.CONTENTS, new PdfString(signature).setHexWriting(true));
            appearance.close(update);
            
            byte[] signedPdfBytes = signedBaos.toByteArray();
            assertNotNull(signedPdfBytes);
            assertTrue(signedPdfBytes.length > pdfBytes.length, "Signed PDF should be larger than original");
            
            // Verify the signed PDF can be read
            try (PdfReader signedReader = new PdfReader(new ByteArrayInputStream(signedPdfBytes))) {
                assertEquals(1, signedReader.getNumberOfPages(), "Signed PDF should have 1 page");
            }
        }
    }

    @Test
    @DisplayName("Test PDF signing with different algorithms")
    void testPdfSigningWithDifferentAlgorithms() throws Exception {
        // Create a simple PDF document
        Document document = new Document();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        PdfWriter writer = PdfWriter.getInstance(document, baos);
        document.open();
        document.add(new Paragraph("Test PDF for signing with different algorithms"));
        document.close();
        
        byte[] pdfBytes = baos.toByteArray();
        
        // Test with SHA-1
        testSigningWithAlgorithm(pdfBytes, "SHA-1");
        
        // Test with SHA-256
        testSigningWithAlgorithm(pdfBytes, "SHA-256");
    }

    private void testSigningWithAlgorithm(byte[] pdfBytes, String algorithm) throws Exception {
        try (PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes));
             ByteArrayOutputStream signedBaos = new ByteArrayOutputStream()) {
            
            PdfStamper stamper = PdfStamper.createSignature(reader, signedBaos, '\0', null, true);
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            
            appearance.setReason("Test signature with " + algorithm);
            appearance.setLocation("Test location");
            
            PdfDictionary dic = new PdfDictionary();
            dic.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE);
            dic.put(PdfName.M, new PdfDate(Calendar.getInstance()));
            
            appearance.setCryptoDictionary(dic);
            appearance.setCertificationLevel(2);
            
            Map<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, 8192);
            appearance.preClose(exc);
            
            byte[] range = appearance.getRangeStream().readAllBytes();
            
            Certificate[] chain = new Certificate[]{testCertificate};
            byte[] signature = cryptoService.signPKCS7(range, keyPair.getPrivate(), chain, algorithm);
            
            PdfDictionary update = new PdfDictionary();
            update.put(PdfName.CONTENTS, new PdfString(signature).setHexWriting(true));
            appearance.close(update);
            
            byte[] signedPdfBytes = signedBaos.toByteArray();
            assertNotNull(signedPdfBytes, "Signed PDF should not be null for " + algorithm);
            assertTrue(signedPdfBytes.length > pdfBytes.length, "Signed PDF should be larger for " + algorithm);
        }
    }

    @Test
    @DisplayName("Test cryptographic operations with real data")
    void testCryptographicOperationsWithRealData() throws Exception {
        // Test AES encryption/decryption
        byte[] data = "This is test data for cryptographic operations".getBytes();
        byte[] key = new byte[32]; // 256-bit key
        byte[] iv = new byte[16];  // 128-bit IV
        
        // Fill with test data
        new java.util.Random().nextBytes(key);
        new java.util.Random().nextBytes(iv);
        
        byte[] encrypted = cryptoService.encryptAES(data, key, iv);
        assertNotNull(encrypted);
        assertNotEquals(data, encrypted);
        
        byte[] decrypted = cryptoService.decryptAES(encrypted, key, iv);
        assertArrayEquals(data, decrypted);
        
        // Test digest operations
        byte[] digest = cryptoService.digest(data, "SHA-256");
        assertNotNull(digest);
        assertEquals(32, digest.length);
        
        // Test that same data produces same digest
        byte[] digest2 = cryptoService.digest(data, "SHA-256");
        assertArrayEquals(digest, digest2);
    }

    @Test
    @DisplayName("Test ASN.1 operations with real data")
    void testASN1OperationsWithRealData() throws Exception {
        byte[] data1 = "First data item".getBytes();
        byte[] data2 = "Second data item".getBytes();
        
        // Test octet string encoding/decoding
        byte[] encoded = cryptoService.encodeASN1OctetString(data1);
        assertNotNull(encoded);
        assertTrue(encoded.length > data1.length);
        
        byte[] decoded = cryptoService.decodeASN1OctetString(encoded);
        assertArrayEquals(data1, decoded);
        
        // Test sequence encoding
        byte[] sequence = cryptoService.encodeASN1Sequence(data1, data2);
        assertNotNull(sequence);
        assertTrue(sequence.length > 0);
        
        // Test set encoding
        byte[] set = cryptoService.encodeASN1Set(data1, data2);
        assertNotNull(set);
        assertTrue(set.length > 0);
        
        // Test UTCTime encoding
        Calendar calendar = Calendar.getInstance();
        byte[] utcTime = cryptoService.encodeASN1UTCTime(calendar);
        assertNotNull(utcTime);
        assertTrue(utcTime.length > 0);
    }

    @Test
    @DisplayName("Test algorithm mappings with real data")
    void testAlgorithmMappingsWithRealData() throws Exception {
        // Test digest OID mappings
        String sha256Oid = cryptoService.getDigestOid("SHA-256");
        assertEquals("2.16.840.1.101.3.4.2.1", sha256Oid);
        
        String sha1Oid = cryptoService.getDigestOid("SHA-1");
        assertEquals("1.3.14.3.2.26", sha1Oid);
        
        // Test algorithm name mappings
        String rsaName = cryptoService.getAlgorithmName("1.2.840.113549.1.1.1");
        assertEquals("RSA", rsaName);
        
        String dsaName = cryptoService.getAlgorithmName("1.2.840.10040.4.1");
        assertEquals("DSA", dsaName);
        
        // Test standard Java name mappings
        String standardName = cryptoService.getStandardJavaName("SHA-256");
        assertEquals("SHA-256", standardName);
        
        String standardName2 = cryptoService.getStandardJavaName("SHA256");
        assertEquals("SHA-256", standardName2);
    }

    @Test
    @DisplayName("Test error handling with invalid data")
    void testErrorHandlingWithInvalidData() {
        // Test null data
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest(null, "SHA-256");
        });
        
        // Test invalid algorithm
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest("test".getBytes(), "INVALID_ALGORITHM");
        });
        
        // Test invalid key size for AES
        assertThrows(GeneralSecurityException.class, () -> {
            byte[] invalidKey = new byte[10]; // Invalid key size
            byte[] iv = new byte[16];
            cryptoService.encryptAES("test".getBytes(), invalidKey, iv);
        });
    }

    @Test
    @DisplayName("Test service provider information")
    void testServiceProviderInformation() {
        ICryptoService service = CryptoServiceProvider.get();
        
        // Test that we can get the service class name
        String className = service.getClass().getSimpleName();
        assertNotNull(className);
        assertTrue(className.contains("CryptoService"));
        
        // Test that we can get the package name
        String packageName = service.getClass().getPackageName();
        assertEquals("org.openpdf.crypto", packageName);
        
        // Test that the service implements the interface
        assertTrue(service instanceof ICryptoService);
    }

    // Helper method to create a mock certificate for testing
    private X509Certificate createMockCertificate(java.security.PublicKey publicKey) throws Exception {
        return new X509Certificate() {
            @Override
            public void checkValidity() {}
            
            @Override
            public void checkValidity(java.util.Date date) {}
            
            @Override
            public int getVersion() { return 3; }
            
            @Override
            public java.math.BigInteger getSerialNumber() { return java.math.BigInteger.ONE; }
            
            @Override
            public java.security.Principal getIssuerDN() { return () -> "CN=Test CA"; }
            
            @Override
            public java.security.Principal getSubjectDN() { return () -> "CN=Test Certificate"; }
            
            @Override
            public java.util.Date getNotBefore() { return new java.util.Date(); }
            
            @Override
            public java.util.Date getNotAfter() { 
                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.YEAR, 1);
                return cal.getTime();
            }
            
            @Override
            public byte[] getTBSCertificate() { return new byte[0]; }
            
            @Override
            public byte[] getSignature() { return new byte[0]; }
            
            @Override
            public String getSigAlgName() { return "SHA256withRSA"; }
            
            @Override
            public String getSigAlgOID() { return "1.2.840.113549.1.1.11"; }
            
            @Override
            public byte[] getSigAlgParams() { return new byte[0]; }
            
            @Override
            public boolean[] getIssuerUniqueID() { return new boolean[0]; }
            
            @Override
            public boolean[] getSubjectUniqueID() { return new boolean[0]; }
            
            @Override
            public boolean[] getKeyUsage() { return new boolean[0]; }
            
            @Override
            public int getBasicConstraints() { return -1; }
            
            @Override
            public byte[] getEncoded() { return new byte[0]; }
            
            @Override
            public void verify(java.security.PublicKey key) {}
            
            @Override
            public void verify(java.security.PublicKey key, String sigProvider) {}
            
            @Override
            public String toString() { return "Mock Certificate"; }
            
            @Override
            public java.security.PublicKey getPublicKey() { return publicKey; }
            
            @Override
            public boolean hasUnsupportedCriticalExtension() { return false; }
            
            @Override
            public java.util.Set<String> getCriticalExtensionOIDs() { return new java.util.HashSet<>(); }
            
            @Override
            public java.util.Set<String> getNonCriticalExtensionOIDs() { return new java.util.HashSet<>(); }
            
            @Override
            public byte[] getExtensionValue(String oid) { return new byte[0]; }
        };
    }
} 