package org.openpdf.text.pdf.crypto;

import org.junit.Test;
import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * Test class for CryptoServiceProvider to verify ServiceLoader functionality
 */
public class CryptoServiceProviderTest {

    @Test
    public void testServiceLoaderLoadsImplementation() {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        assertNotNull("CryptoService should not be null", cryptoService);
        assertTrue("CryptoService should be an instance of ICryptoService", 
                  cryptoService instanceof ICryptoService);
    }

    @Test
    public void testDigestOperation() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        byte[] data = "Hello, World!".getBytes();
        byte[] digest = cryptoService.digest(data, "SHA-256");
        
        assertNotNull("Digest should not be null", digest);
        assertTrue("Digest should have length > 0", digest.length > 0);
        
        // Verify it matches Java's built-in SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] expectedDigest = md.digest(data);
        assertArrayEquals("Digest should match expected value", expectedDigest, digest);
    }

    @Test
    public void testDigestOidMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String oid = cryptoService.getDigestOid("SHA-256");
        assertEquals("SHA-256 OID should be correct", "2.16.840.1.101.3.4.2.1", oid);
        
        String name = cryptoService.getDigestName(oid);
        assertEquals("Digest name should be correct", "SHA-256", name);
    }

    @Test
    public void testAlgorithmNameMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String name = cryptoService.getAlgorithmName("1.2.840.113549.1.1.1");
        assertEquals("RSA algorithm name should be correct", "RSA", name);
    }

    @Test
    public void testStandardJavaNameMapping() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        
        String name = cryptoService.getStandardJavaName("SHA-256");
        assertEquals("Standard Java name should be correct", "SHA-256", name);
    }

    @Test
    public void testASN1Operations() throws GeneralSecurityException {
        ICryptoService cryptoService = CryptoServiceProvider.get();
        byte[] data = "Test data".getBytes();
        
        // Test octet string encoding/decoding
        byte[] encoded = cryptoService.encodeASN1OctetString(data);
        assertNotNull("Encoded data should not be null", encoded);
        assertTrue("Encoded data should have length > 0", encoded.length > 0);
        
        byte[] decoded = cryptoService.decodeASN1OctetString(encoded);
        assertArrayEquals("Decoded data should match original", data, decoded);
    }

    @Test
    public void testSingletonBehavior() {
        ICryptoService service1 = CryptoServiceProvider.get();
        ICryptoService service2 = CryptoServiceProvider.get();
        
        assertSame("CryptoServiceProvider should return the same instance", service1, service2);
    }
} 