/*
 * $Id: PdfPublicKeySecurityHandler.java 4055 2009-08-30 23:47:33Z psoares33 $
 * $Name$
 *
 * Copyright 2006 Paulo Soares
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
 * the Initial Developer are Copyright (C) 1999-2007 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2000-2007 by Paulo Soares. All Rights Reserved.
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

/*
      The below 2 methods are from pdfbox.

      private DERObject createDERForRecipient(byte[] in, X509Certificate cert) ;
      private KeyTransRecipientInfo computeRecipientInfo(X509Certificate x509certificate, byte[] abyte0);

      2006-11-22 Aiken Sam.
 */

/*
  Copyright (c) 2003-2006, www.pdfbox.org
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
  3. Neither the name of pdfbox; nor the names of its
     contributors may be used to endorse or promote products derived from this
     software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  http://www.pdfbox.org

 */

package org.openpdf.text.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.openpdf.text.pdf.crypto.CryptoServiceProvider;

/**
 * @author Aiken Sam (aikensam@ieee.org)
 */
public class PdfPublicKeySecurityHandler extends PdfEncryption {

    private final List<Certificate> recipients = new ArrayList<>();
    private final List<byte[]> envelopedData = new ArrayList<>();

    public PdfPublicKeySecurityHandler() {
        super(true); // Skip creating another PdfPublicKeySecurityHandler
    }

    /**
     * Add a recipient
     */
    public void addRecipient(Certificate cert) {
        recipients.add(cert);
    }

    /**
     * Get the number of recipients
     */
    public int getRecipientsSize() {
        return recipients.size();
    }

    /**
     * Get a recipient
     */
    public Certificate getRecipient(int index) {
        return recipients.get(index);
    }

    /**
     * Get the enveloped data
     */
    public byte[] getEnvelopedData(int index) {
        return envelopedData.get(index);
    }

    /**
     * Prepare the encryption
     */
    public void prepareForEncryption() throws GeneralSecurityException {
        if (recipients.isEmpty()) {
            throw new GeneralSecurityException("No recipients specified");
        }
        
        // Generate content encryption key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey contentKey = keyGen.generateKey();
        
        // Create enveloped data for each recipient
        for (Certificate recipient : recipients) {
            byte[] envelope = CryptoServiceProvider.get().createEnvelopedData(
                List.of(recipient), contentKey.getEncoded());
            envelopedData.add(envelope);
        }
    }

    /**
     * Decrypt the enveloped data
     */
    public byte[] decryptEnvelopedData(byte[] envelope, PrivateKey privateKey, Certificate certificate) 
            throws GeneralSecurityException {
        return CryptoServiceProvider.get().extractEnvelopedData(envelope, privateKey, certificate);
    }

    /**
     * Create envelope for a recipient
     */
    private byte[] createEnvelope(List<Certificate> recipients, byte[] data) throws Exception {
        return CryptoServiceProvider.get().createEnvelopedData(recipients, data);
    }

    /**
     * Get encoded recipients
     */
    public PdfArray getEncodedRecipients() throws Exception {
        PdfArray array = new PdfArray();
        for (byte[] envelope : envelopedData) {
            array.add(new PdfString(envelope));
        }
        return array;
    }

    /**
     * Get seed for encryption
     */
    public byte[] getSeed() {
        // Generate a random seed
        byte[] seed = new byte[20];
        new SecureRandom().nextBytes(seed);
        return seed;
    }

    /**
     * Get encoded recipient at index
     */
    public byte[] getEncodedRecipient(int index) {
        return envelopedData.get(index);
    }
}
