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
package com.lowagie.text.pdf.crypto;

import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

/**
 * Interface for cryptographic services in OpenPDF.
 * This interface provides a modular approach to cryptographic operations,
 * allowing different implementations (e.g., standard Bouncy Castle, FIPS-compliant Bouncy Castle)
 * to be used interchangeably.
 * 
 * @since 2.4.0
 */
public interface ICryptoService {
    
    /**
     * Creates a digest of the given data using the specified algorithm.
     * 
     * @param data the data to digest
     * @param algorithm the digest algorithm (e.g., "SHA-256", "SHA-512")
     * @return the digest bytes
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] digest(byte[] data, String algorithm) throws GeneralSecurityException;
    
    /**
     * Encrypts data using AES encryption.
     * 
     * @param data the data to encrypt
     * @param key the encryption key
     * @param iv the initialization vector
     * @return the encrypted data
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] encryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException;
    
    /**
     * Decrypts data using AES decryption.
     * 
     * @param data the data to decrypt
     * @param key the decryption key
     * @param iv the initialization vector
     * @return the decrypted data
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] decryptAES(byte[] data, byte[] key, byte[] iv) throws GeneralSecurityException;
    
    /**
     * Creates a PKCS#7 signature.
     * 
     * @param data the data to sign
     * @param privateKey the private key for signing
     * @param certificate the certificate chain
     * @param digestAlgorithm the digest algorithm to use
     * @return the signature bytes
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] createPKCS7Signature(byte[] data, java.security.PrivateKey privateKey, 
                               Certificate[] certificate, String digestAlgorithm) throws GeneralSecurityException;
    
    /**
     * Verifies a PKCS#7 signature.
     * 
     * @param data the original data
     * @param signature the signature to verify
     * @param certificate the certificate to verify against
     * @return true if the signature is valid, false otherwise
     * @throws GeneralSecurityException if the operation fails
     */
    boolean verifyPKCS7Signature(byte[] data, byte[] signature, Certificate certificate) throws GeneralSecurityException;
    
    /**
     * Creates CMS enveloped data.
     * 
     * @param data the data to encrypt
     * @param certificate the recipient certificate
     * @return the CMS enveloped data
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] createEnvelopedData(byte[] data, Certificate certificate) throws GeneralSecurityException;
    
    /**
     * Extracts data from CMS enveloped data.
     * 
     * @param envelopedData the CMS enveloped data
     * @param privateKey the private key for decryption
     * @param certificate the certificate
     * @return the extracted data
     * @throws GeneralSecurityException if the operation fails
     */
    byte[] extractEnvelopedData(byte[] envelopedData, java.security.PrivateKey privateKey, Certificate certificate) throws GeneralSecurityException;
    
    /**
     * Verifies a certificate.
     * 
     * @param cert the certificate to verify
     * @param crls the certificate revocation lists
     * @param calendar the calendar for validation
     * @return null if valid, error message if invalid
     * @throws GeneralSecurityException if the operation fails
     */
    String verifyCertificate(X509Certificate cert, List<Object> crls, Calendar calendar) throws GeneralSecurityException;
    
    /**
     * Verifies multiple certificates.
     * 
     * @param certs the certificates to verify
     * @param keystore the keystore for validation
     * @param crls the certificate revocation lists
     * @param calendar the calendar for validation
     * @return array of verification results
     * @throws GeneralSecurityException if the operation fails
     */
    Object[] verifyCertificates(Certificate[] certs, java.security.KeyStore keystore, 
                               List<Object> crls, Calendar calendar) throws GeneralSecurityException;
    
    /**
     * Checks certificate encoding.
     * 
     * @param certificate the certificate to check
     * @throws GeneralSecurityException if the encoding is invalid
     */
    void checkCertificateEncoding(Certificate certificate) throws GeneralSecurityException;
    
    /**
     * Gets the standard Java name for an algorithm.
     * 
     * @param algorithmName the algorithm name
     * @return the standard Java name
     * @throws GeneralSecurityException if the algorithm is not supported
     */
    String getStandardJavaName(String algorithmName) throws GeneralSecurityException;
    
    /**
     * Gets the service provider name.
     * 
     * @return the service provider name
     */
    String getServiceProviderName();
} 