/*
 * Copyright 2004 by Paulo Soares.
 *
 * The contents of this file are subject to the Mozilla Public License Version 1.1
 * (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the License.
 *
 * The Original Code is 'iText, a free JAVA-PDF library'.
 *
 * The Initial Developer of the Original Code is Bruno Lowagie. Portions created by
 * the Initial Developer are Copyright (C) 1999, 2000, 2001, 2002 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000, 2001, 2002 by Paulo Soares. All Rights Reserved.
 *
 * Contributor(s): all the names of the contributors are added in the source code
 * where applicable.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * LGPL license (the "GNU LIBRARY GENERAL PUBLIC LICENSE"), in which case the
 * provisions of LGPL are applicable instead of those above.  If you wish to
 * allow use of your version of this file only under the terms of the LGPL
 * License and not to allow others to use your version of this file under
 * the MPL, indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the LGPL.
 * If you do not delete the provisions above, a recipient may use your version
 * of this file under either the MPL or the GNU LIBRARY GENERAL PUBLIC LICENSE.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MPL as stated above or under the terms of the GNU
 * Library General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Library general Public License for more
 * details.
 *
 * If you didn't download this code from the following link, you should check if
 * you aren't using an obsolete version:
 * https://github.com/LibrePDF/OpenPDF
 */
package org.openpdf.text.pdf;

import org.openpdf.text.ExceptionConverter;
import org.openpdf.text.error_messages.MessageLocalization;
import org.openpdf.text.pdf.crypto.CryptoServiceProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * This class does all the processing related to signing and verifying a PKCS#7 signature.
 * <p>
 * Now uses ICryptoService for all cryptographic operations.
 */
public class PdfPKCS7 {

    private static final String ID_PKCS7_DATA = "1.2.840.113549.1.7.1";
    private static final String ID_PKCS7_SIGNED_DATA = "1.2.840.113549.1.7.2";
    private static final String ID_RSA = "1.2.840.113549.1.1.1";
    private static final String ID_DSA = "1.2.840.10040.4.1";
    private static final String ID_ECDSA = "1.2.840.10045.2.1";
    private static final String ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    private static final String ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    private static final String ID_SIGNING_TIME = "1.2.840.113549.1.9.5";
    private static final String ID_ADBE_REVOCATION = "1.2.840.113583.1.1.8";

    private final List<Certificate> certs;
    private final List<CRL> crls;
    private final String provider;
    private byte[] sigAttr;
    private byte[] digestAttr;
    private int version, signerversion;
    private Set<String> digestalgos;
    private List<Certificate> signCerts;
    private X509Certificate signCert;
    private byte[] digest;
    private MessageDigest messageDigest;
    private String digestAlgorithm, digestEncryptionAlgorithm;
    private Signature sig;
    private transient PrivateKey privKey;
    private byte[] RSAdata;
    private boolean verified;
    private boolean verifyResult;
    private byte[] externalDigest;
    private byte[] externalRSAdata;
    private String reason;
    private String location;
    private Calendar signDate;
    private String signName;
    private Object timeStampToken;
    private Object basicResp;

    /**
     * Constructor for verification
     */
    @SuppressWarnings("unchecked")
    public PdfPKCS7(byte[] contentsKey, byte[] certsKey, String provider) {
        try {
            this.provider = provider;
            this.certs = new ArrayList<>();
            this.crls = new ArrayList<>();
            
            // Parse certificates using crypto service
            if (certsKey != null) {
                Certificate[] certificates = CryptoServiceProvider.get().parseCertificates(certsKey);
                this.certs.addAll(Arrays.asList(certificates));
                this.signCerts = this.certs;
                this.signCert = (X509Certificate) this.certs.iterator().next();
            }
            
            // Parse digest from contents
            if (contentsKey != null) {
                this.digest = CryptoServiceProvider.get().decodeASN1OctetString(contentsKey);
            }
            
            // Initialize signature verification
            if (this.signCert != null) {
                this.sig = Signature.getInstance("SHA1withRSA");
                this.sig.initVerify(this.signCert.getPublicKey());
            }
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Constructor for verification
     */
    @SuppressWarnings("unchecked")
    public PdfPKCS7(byte[] contentsKey, String provider) {
        this(contentsKey, null, provider);
    }

    /**
     * Constructor for signing
     */
    public PdfPKCS7(PrivateKey privKey, Certificate[] certChain, CRL[] crlList,
            String hashAlgorithm, String provider, boolean hasRSAdata)
            throws InvalidKeyException, NoSuchProviderException,
            NoSuchAlgorithmException {
        this.privKey = privKey;
        this.provider = provider;

        this.digestAlgorithm = CryptoServiceProvider.get().getDigestOid(hashAlgorithm.toUpperCase());
        if (this.digestAlgorithm == null) {
            throw new NoSuchAlgorithmException(
                    MessageLocalization.getComposedMessage("unknown.hash.algorithm.1",
                            hashAlgorithm));
        }

        this.version = this.signerversion = 1;
        this.certs = new ArrayList<>();
        this.crls = new ArrayList<>();
        this.digestalgos = new HashSet<>();
        this.digestalgos.add(this.digestAlgorithm);

        // Copy in the certificates and crls used to sign the private key
        this.signCert = (X509Certificate) certChain[0];
        this.certs.addAll(Arrays.asList(certChain));

        if (crlList != null) {
            this.crls.addAll(Arrays.asList(crlList));
        }

        if (privKey != null) {
            // Find out what the digestEncryptionAlgorithm is
            this.digestEncryptionAlgorithm = privKey.getAlgorithm();
            if (this.digestEncryptionAlgorithm.equals("RSA")) {
                this.digestEncryptionAlgorithm = ID_RSA;
            } else if (this.digestEncryptionAlgorithm.equals("DSA")) {
                this.digestEncryptionAlgorithm = ID_DSA;
            } else if (this.digestEncryptionAlgorithm.equals("EC") || this.digestEncryptionAlgorithm.equals("ECDSA")) {
                this.digestEncryptionAlgorithm = ID_ECDSA;
            } else {
                throw new NoSuchAlgorithmException(
                        MessageLocalization.getComposedMessage("unknown.key.algorithm.1",
                                this.digestEncryptionAlgorithm));
            }
        }

        if (hasRSAdata) {
            this.RSAdata = new byte[0];
            this.messageDigest = MessageDigest.getInstance(CryptoServiceProvider.get().getStandardJavaName(this.digestAlgorithm));
        }

        if (privKey != null) {
            this.sig = Signature.getInstance(this.digestAlgorithm);
            this.sig.initSign(privKey);
        }
    }

    /**
     * Loads the default root certificates
     */
    public static KeyStore loadCacertsKeyStore() {
        return loadCacertsKeyStore(null);
    }

    /**
     * Loads the default root certificates with the specified provider
     */
    public static KeyStore loadCacertsKeyStore(String provider) {
        try {
            KeyStore keystore = KeyStore.getInstance("JKS");
            String filename = System.getProperty("java.home") + "/lib/security/cacerts";
            File file = new File(filename);
            if (file.exists()) {
                try (FileInputStream fin = new FileInputStream(file)) {
                    keystore.load(fin, null);
                }
            }
            return keystore;
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Verifies a certificate
     */
    public static String verifyCertificate(X509Certificate cert, Collection crls, Calendar calendar) {
        try {
            return CryptoServiceProvider.get().verifyCertificate(cert, new ArrayList<>(crls), calendar);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Verifies certificates
     */
    public static Object[] verifyCertificates(Certificate[] certs, KeyStore keystore, Collection crls, Calendar calendar) {
        try {
            return CryptoServiceProvider.get().verifyCertificates(certs, keystore, new ArrayList<>(crls), calendar);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the OCSP URL from a certificate
     */
    public static String getOCSPURL(X509Certificate certificate) {
        try {
            return CryptoServiceProvider.get().getOCSPURL(certificate);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the digest name for a certain id
     */
    public static String getDigest(String oid) {
        try {
            return CryptoServiceProvider.get().getDigestName(oid);
        } catch (Exception e) {
            return oid;
        }
    }

    /**
     * Gets the algorithm name for a certain id
     */
    public static String getAlgorithm(String oid) {
        try {
            return CryptoServiceProvider.get().getAlgorithmName(oid);
        } catch (Exception e) {
            return oid;
        }
    }

    /**
     * Gets the oid for given digest name
     */
    public static String getDigestOid(String digestName) {
        try {
            return CryptoServiceProvider.get().getDigestOid(digestName);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the standard Java name for an algorithm
     */
    public static String getStandardJavaName(String algName) {
        try {
            return CryptoServiceProvider.get().getStandardJavaName(algName);
        } catch (Exception e) {
            return algName;
        }
    }

    /**
     * Gets the timestamp token
     */
    public Object getTimeStampToken() {
        return timeStampToken;
    }

    /**
     * Gets the timestamp date
     */
    public Calendar getTimeStampDate() {
        // Implementation would depend on the specific timestamp token format
        return null;
    }

    /**
     * Gets the OCSP response
     */
    public Object getOcsp() {
        return basicResp;
    }

    /**
     * Updates the signature with data
     */
    public void update(byte[] buf, int off, int len) throws SignatureException {
        if (sig != null) {
            sig.update(buf, off, len);
        }
        if (messageDigest != null) {
            messageDigest.update(buf, off, len);
        }
    }

    /**
     * Verifies the signature
     */
    public boolean verify() throws SignatureException {
        if (verified) {
            return verifyResult;
        }
        verified = true;
        verifyResult = false;
        if (externalDigest != null) {
            digest = externalDigest;
        } else if (sig != null) {
            digest = sig.sign();
        }
        if (digest != null) {
            verifyResult = sig.verify(digest);
        }
        return verifyResult;
    }

    /**
     * Verifies timestamp imprint
     */
    public boolean verifyTimestampImprint() throws NoSuchAlgorithmException {
        if (timeStampToken == null) {
            return false;
        }
        // Implementation would depend on the specific timestamp token format
        return false;
    }

    /**
     * Gets all certificates
     */
    public Certificate[] getCertificates() {
        return certs.toArray(new Certificate[0]);
    }

    /**
     * Gets the signing certificate chain
     */
    public Certificate[] getSignCertificateChain() {
        return signCerts.toArray(new Certificate[0]);
    }

    /**
     * Gets the CRLs
     */
    public Collection getCRLs() {
        return crls;
    }

    /**
     * Gets the signing certificate
     */
    public X509Certificate getSigningCertificate() {
        return signCert;
    }

    /**
     * Gets the version
     */
    public int getVersion() {
        return version;
    }

    /**
     * Gets the signing info version
     */
    public int getSigningInfoVersion() {
        return signerversion;
    }

    /**
     * Gets the digest algorithm
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Gets the hash algorithm
     */
    public String getHashAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Checks if revocation is valid
     */
    public boolean isRevocationValid() {
        if (basicResp == null) {
            return false;
        }
        if (signCerts.size() < 2) {
            return false;
        }
        try {
            X509Certificate[] cs = (X509Certificate[]) getSignCertificateChain();
            X509Certificate sigcer = getSigningCertificate();
            X509Certificate isscer = cs[1];
            
            // Use crypto service to validate OCSP response
            return CryptoServiceProvider.get().validateOCSPResponse(
                (byte[]) basicResp, isscer, sigcer);
        } catch (Exception ignored) {
        }
        return false;
    }

    /**
     * Gets the encoded PKCS#1
     */
    public byte[] getEncodedPKCS1() {
        try {
            if (externalDigest != null) {
                digest = externalDigest;
            } else if (sig != null) {
                digest = sig.sign();
            }
            return CryptoServiceProvider.get().encodeASN1OctetString(digest);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Sets external digest
     */
    public void setExternalDigest(byte[] digest, byte[] RSAdata, String digestEncryptionAlgorithm) {
        this.externalDigest = digest;
        this.externalRSAdata = RSAdata;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
    }

    /**
     * Gets the encoded PKCS#7
     */
    public byte[] getEncodedPKCS7() {
        try {
            return getEncodedPKCS7(null, null);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the encoded PKCS#7 with signing time
     */
    public byte[] getEncodedPKCS7(byte[] secondDigest, Calendar signingTime) {
        try {
            return getEncodedPKCS7(secondDigest, signingTime, null, null);
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the encoded PKCS#7 with timestamp and OCSP
     */
    public byte[] getEncodedPKCS7(byte[] secondDigest, Calendar signingTime, TSAClient tsaClient, byte[] ocsp) {
        try {
            if (externalDigest != null) {
                digest = externalDigest;
            } else if (sig != null) {
                digest = sig.sign();
            }

            byte[] timeStampToken = null;
            if (tsaClient != null) {
                timeStampToken = tsaClient.getTimeStampToken(this, digest);
            }

            if (timeStampToken != null) {
                return CryptoServiceProvider.get().createPKCS7SignatureWithTimestamp(
                    secondDigest != null ? secondDigest : digest,
                    privKey, signCerts.toArray(new Certificate[0]), digestAlgorithm,
                    signingTime, reason, location, timeStampToken);
            } else if (ocsp != null) {
                return CryptoServiceProvider.get().createPKCS7SignatureWithOCSP(
                    secondDigest != null ? secondDigest : digest,
                    privKey, signCerts.toArray(new Certificate[0]), digestAlgorithm,
                    signingTime, reason, location, ocsp);
            } else {
                return CryptoServiceProvider.get().createPKCS7Signature(
                    secondDigest != null ? secondDigest : digest,
                    privKey, signCerts.toArray(new Certificate[0]), digestAlgorithm,
                    signingTime, reason, location);
            }
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the authenticated attribute bytes
     */
    public byte[] getAuthenticatedAttributeBytes(byte[] secondDigest, Calendar signingTime, byte[] ocsp) {
        try {
            // This would need to be implemented based on the specific ASN.1 structure needed
            return new byte[0];
        } catch (Exception e) {
            throw new ExceptionConverter(e);
        }
    }

    /**
     * Gets the reason
     */
    public String getReason() {
        return reason;
    }

    /**
     * Sets the reason
     */
    public void setReason(String reason) {
        this.reason = reason;
    }

    /**
     * Gets the location
     */
    public String getLocation() {
        return location;
    }

    /**
     * Sets the location
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * Gets the sign date
     */
    public Calendar getSignDate() {
        return signDate;
    }

    /**
     * Sets the sign date
     */
    public void setSignDate(Calendar signDate) {
        this.signDate = signDate;
    }

    /**
     * Gets the sign name
     */
    public String getSignName() {
        return signName;
    }

    /**
     * Sets the sign name
     */
    public void setSignName(String signName) {
        this.signName = signName;
    }

    /**
     * X509Name class for certificate name handling
     */
    public static class X509Name {
        private Map<String, List<String>> valuesMap = new HashMap<>();

        public X509Name(String dirName) {
            // Simplified implementation - would need full parsing logic
        }

        public String getField(String name) {
            List<String> values = valuesMap.get(name);
            return values != null && !values.isEmpty() ? values.get(0) : null;
        }

        public List<String> getFieldsByName(String name) {
            return valuesMap.getOrDefault(name, new ArrayList<>());
        }

        public Map<String, List<String>> getAllFields() {
            return new HashMap<>(valuesMap);
        }

        @Override
        public String toString() {
            return valuesMap.toString();
        }
    }

    /**
     * X509NameTokenizer for parsing certificate names
     */
    public static class X509NameTokenizer {
        private final String oid;
        private final StringBuffer buf = new StringBuffer();
        private int index;

        public X509NameTokenizer(String oid) {
            this.oid = oid;
        }

        public boolean hasMoreTokens() {
            return index < oid.length();
        }

        public String nextToken() {
            // Simplified implementation - would need full parsing logic
            return "";
        }
    }
}
