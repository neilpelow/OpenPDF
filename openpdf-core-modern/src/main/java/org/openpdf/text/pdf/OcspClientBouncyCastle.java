/*
 * $Id: OcspClientBouncyCastle.java 4065 2009-09-16 23:09:11Z psoares33 $
 *
 * Copyright 2009 Paulo Soares
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
 * the Initial Developer are Copyright (C) 1999-2005 by Bruno Lowagie.
 * All Rights Reserved.
 * Co-Developer of the code is Paulo Soares. Portions created by the Co-Developer
 * are Copyright (C) 2009 by Paulo Soares. All Rights Reserved.
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
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.io.ByteArrayOutputStream;

/**
 * OcspClient implementation using ICryptoService.
 *
 * @author psoares
 * @since 2.1.6
 */
public class OcspClientBouncyCastle implements OcspClient {

    /**
     * root certificate
     */
    private final X509Certificate rootCert;
    /**
     * check certificate
     */
    private final X509Certificate checkCert;
    /**
     * OCSP URL
     */
    private final String url;
    /**
     * HTTP proxy used to access the OCSP URL
     */
    private Proxy proxy;

    /**
     * Creates an instance of an OcspClient that will be using ICryptoService.
     *
     * @param checkCert the check certificate
     * @param rootCert  the root certificate
     * @param url       the OCSP URL
     */
    public OcspClientBouncyCastle(X509Certificate checkCert,
            X509Certificate rootCert, String url) {
        this.checkCert = checkCert;
        this.rootCert = rootCert;
        this.url = url;
    }

    /**
     * Generates an OCSP request using ICryptoService.
     *
     * @param issuerCert   certificate of the issuer
     * @param serialNumber serial number
     * @return an OCSP request
     */
    private static byte[] generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber) throws Exception {
        return CryptoServiceProvider.get().generateOCSPRequest(issuerCert, serialNumber);
    }

    /**
     * @return a byte array
     * @see org.openpdf.text.pdf.OcspClient
     */
    @Override
    public byte[] getEncoded() {
        try {
            byte[] array = generateOCSPRequest(rootCert,
                    checkCert.getSerialNumber());
            URL urlt = new URL(url);
            Proxy tmpProxy = proxy == null ? Proxy.NO_PROXY : proxy;
            HttpURLConnection con = (HttpURLConnection) urlt.openConnection(tmpProxy);
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);
            OutputStream out = con.getOutputStream();
            DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(
                    out));
            dataOut.write(array);
            dataOut.flush();
            dataOut.close();
            if (con.getResponseCode() / 100 != 2) {
                throw new IOException(MessageLocalization.getComposedMessage(
                        "invalid.http.response.1", con.getResponseCode()));
            }
            // Get Response
            InputStream in = (InputStream) con.getContent();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) >= 0) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] ocspResponse = baos.toByteArray();
            
            // Validate the OCSP response using crypto service
            if (CryptoServiceProvider.get().validateOCSPResponse(ocspResponse, rootCert, checkCert)) {
                return ocspResponse;
            } else {
                throw new IOException(MessageLocalization.getComposedMessage("ocsp.status.is.revoked"));
            }
        } catch (Exception ex) {
            throw new ExceptionConverter(ex);
        }
    }

    /**
     * Returns Proxy object used for URL connections.
     *
     * @return configured proxy
     */
    public Proxy getProxy() {
        return proxy;
    }

    /**
     * Sets Proxy which will be used for URL connection.
     *
     * @param aProxy Proxy to set
     */
    public void setProxy(final Proxy aProxy) {
        this.proxy = aProxy;
    }
}
