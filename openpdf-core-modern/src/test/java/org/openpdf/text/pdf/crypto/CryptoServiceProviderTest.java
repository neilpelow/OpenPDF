package org.openpdf.text.pdf.crypto;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Test class for CryptoServiceProvider to verify ServiceLoader functionality
 */
public class CryptoServiceProviderTest {

    @Test
    public void testServiceLoaderLoadsImplementation() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        assertNotNull(cryptoService, "CryptoService should not be null");
        assertTrue(cryptoService instanceof ICryptoService, "CryptoService should be an instance of ICryptoService");
    }

    @Test
    public void testDigestOperation() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        byte[] data = "Hello, World!".getBytes();
        byte[] digest = cryptoService.digest(data, "SHA-256");
        
        assertNotNull(digest, "Digest should not be null");
        assertTrue(digest.length > 0, "Digest should have length > 0");
        
        // Verify it matches Java's built-in SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] expectedDigest = md.digest(data);
        assertArrayEquals(expectedDigest, digest, "Digest should match expected value");
    }

    @Test
    public void testDigestOidMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String oid = cryptoService.getDigestOid("SHA-256");
        assertEquals("2.16.840.1.101.3.4.2.1", oid, "SHA-256 OID should be correct");
        
        String name = cryptoService.getDigestName(oid);
        assertEquals("SHA-256", name, "Digest name should be correct");
    }

    @Test
    public void testAlgorithmNameMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String name = cryptoService.getAlgorithmName("1.2.840.113549.1.1.1");
        assertEquals("RSA", name, "RSA algorithm name should be correct");
    }

    @Test
    public void testStandardJavaNameMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String name = cryptoService.getStandardJavaName("SHA-256");
        assertEquals("SHA-256", name, "Standard Java name should be correct");
    }

    @Test
    public void testASN1Operations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        byte[] data = "Test data".getBytes();
        
        // Test octet string encoding/decoding
        byte[] encoded = cryptoService.encodeASN1OctetString(data);
        assertNotNull(encoded, "Encoded data should not be null");
        assertTrue(encoded.length > 0, "Encoded data should have length > 0");
        
        byte[] decoded = cryptoService.decodeASN1OctetString(encoded);
        assertArrayEquals(data, decoded, "Decoded data should match original");
    }

    @Test
    public void testSingletonBehavior() {
        ICryptoService service1 = CryptoServiceProvider.get();
        ICryptoService service2 = CryptoServiceProvider.get();
        
        assertSame(service1, service2, "CryptoServiceProvider should return the same instance");
    }
} 