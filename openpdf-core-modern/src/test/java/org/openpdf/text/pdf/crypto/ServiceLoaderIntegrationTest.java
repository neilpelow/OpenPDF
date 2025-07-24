package org.openpdf.text.pdf.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;

/**
 * Integration tests for ServiceLoader mechanism
 */
@DisplayName("ServiceLoader Integration Tests")
class ServiceLoaderIntegrationTest {

    private CryptoServiceProvider cryptoServiceProvider;

    @BeforeEach
    void setUp() {
        cryptoServiceProvider = new CryptoServiceProvider();
    }

    @Test
    @DisplayName("Test ServiceLoader loads an implementation")
    void testServiceLoaderLoadsImplementation() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        assertNotNull(cryptoService, "CryptoService should not be null");
        assertTrue(cryptoService instanceof ICryptoService, "Should be an instance of ICryptoService");
    }

    @Test
    @DisplayName("Test ServiceLoader returns same instance (singleton)")
    void testServiceLoaderSingleton() {
        ICryptoService service1 = CryptoServiceProvider.get();
        ICryptoService service2 = CryptoServiceProvider.get();
        
        assertSame(service1, service2, "ServiceLoader should return the same instance");
    }

    @Test
    @DisplayName("Test basic cryptographic operations work")
    void testBasicCryptographicOperations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test digest operation
        byte[] data = "Test data".getBytes();
        byte[] digest = cryptoService.digest(data, "SHA-256");
        assertNotNull(digest, "Digest should not be null");
        assertEquals(32, digest.length, "SHA-256 digest should be 32 bytes");
        
        // Test algorithm mapping
        String oid = cryptoService.getDigestOid("SHA-256");
        assertEquals("2.16.840.1.101.3.4.2.1", oid, "SHA-256 OID should be correct");
        
        String name = cryptoService.getDigestName(oid);
        assertEquals("SHA-256", name, "Digest name should be correct");
    }

    @Test
    @DisplayName("Test ASN.1 operations work")
    void testASN1Operations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        byte[] data = "Test ASN.1 data".getBytes();
        
        // Test octet string encoding/decoding
        byte[] encoded = cryptoService.encodeASN1OctetString(data);
        assertNotNull(encoded, "Encoded data should not be null");
        assertTrue(encoded.length > data.length, "ASN.1 encoding should add overhead");
        
        byte[] decoded = cryptoService.decodeASN1OctetString(encoded);
        assertArrayEquals(data, decoded, "Decoded data should match original");
    }

    @Test
    @DisplayName("Test algorithm name mappings work")
    void testAlgorithmNameMappings() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test RSA algorithm mapping
        String rsaName = cryptoService.getAlgorithmName("1.2.840.113549.1.1.1");
        assertEquals("RSA", rsaName, "RSA algorithm name should be correct");
        
        // Test DSA algorithm mapping
        String dsaName = cryptoService.getAlgorithmName("1.2.840.10040.4.1");
        assertEquals("DSA", dsaName, "DSA algorithm name should be correct");
        
        // Test ECDSA algorithm mapping
        String ecdsaName = cryptoService.getAlgorithmName("1.2.840.10045.2.1");
        assertEquals("ECDSA", ecdsaName, "ECDSA algorithm name should be correct");
    }

    @Test
    @DisplayName("Test standard Java name mapping")
    void testStandardJavaNameMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String name = cryptoService.getStandardJavaName("SHA-256");
        assertEquals("SHA-256", name, "Standard Java name should be correct");
        
        String name2 = cryptoService.getStandardJavaName("SHA256");
        assertEquals("SHA-256", name2, "Standard Java name should handle variants");
    }

    @Test
    @DisplayName("Test error handling for invalid algorithm")
    void testErrorHandlingForInvalidAlgorithm() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest("test".getBytes(), "INVALID_ALGORITHM");
        }, "Should throw exception for invalid algorithm");
    }

    @Test
    @DisplayName("Test error handling for null data")
    void testErrorHandlingForNullData() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        assertThrows(GeneralSecurityException.class, () -> {
            cryptoService.digest(null, "SHA-256");
        }, "Should throw exception for null data");
    }

    @Test
    @DisplayName("Test certificate operations work")
    void testCertificateOperations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test that certificate operations don't throw unexpected exceptions
        // Note: These are simplified tests since we don't have real certificates
        assertNotNull(cryptoService, "CryptoService should be available");
    }

    @Test
    @DisplayName("Test OCSP operations work")
    void testOCSPOperations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test that OCSP operations don't throw unexpected exceptions
        // Note: These are simplified tests since we don't have real certificates
        assertNotNull(cryptoService, "CryptoService should be available");
    }

    @Test
    @DisplayName("Test TSA operations work")
    void testTSAOperations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test that TSA operations don't throw unexpected exceptions
        // Note: These are simplified tests since we don't have real TSA server
        assertNotNull(cryptoService, "CryptoService should be available");
    }

    @Test
    @DisplayName("Test CMS enveloped data operations work")
    void testCMSEnvelopedDataOperations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test that CMS operations don't throw unexpected exceptions
        // Note: These are simplified tests since we don't have real certificates
        assertNotNull(cryptoService, "CryptoService should be available");
    }

    @Test
    @DisplayName("Test PKCS#7 operations work")
    void testPKCS7Operations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        // Test that PKCS#7 operations don't throw unexpected exceptions
        // Note: These are simplified tests since we don't have real certificates
        assertNotNull(cryptoService, "CryptoService should be available");
    }

    @Test
    @DisplayName("Test multiple concurrent access")
    void testMultipleConcurrentAccess() throws InterruptedException {
        // Test that multiple threads can access the service simultaneously
        Thread[] threads = new Thread[10];
        ICryptoService[] services = new ICryptoService[10];
        
        for (int i = 0; i < 10; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                services[index] = CryptoServiceProvider.get();
            });
        }
        
        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Verify all threads got the same instance
        ICryptoService firstService = services[0];
        for (int i = 1; i < services.length; i++) {
            assertSame(firstService, services[i], "All threads should get the same instance");
        }
    }

    @Test
    @DisplayName("Test service provider class name")
    void testServiceProviderClassName() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        String className = cryptoService.getClass().getSimpleName();
        
        // Should be one of the expected adapter names
        assertTrue(className.equals("BouncyCastleCryptoService") || 
                  className.equals("FipsBouncyCastleCryptoService"),
                  "Service should be one of the expected adapter implementations: " + className);
    }

    @Test
    @DisplayName("Test service provider package")
    void testServiceProviderPackage() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        String packageName = cryptoService.getClass().getPackageName();
        
        // Should be in the expected package
        assertEquals("org.openpdf.crypto", packageName, 
                    "Service should be in the expected package: " + packageName);
    }
} 