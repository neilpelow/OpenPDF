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

import java.util.ServiceLoader;

/**
 * Provider for cryptographic services in OpenPDF.
 * This class uses the ServiceLoader mechanism to discover and provide
 * implementations of the ICryptoService interface.
 * 
 * @since 2.4.0
 */
public class CryptoServiceProvider {
    
    private static volatile ICryptoService cryptoService;
    private static final Object lock = new Object();
    
    /**
     * Gets the cryptographic service implementation.
     * Uses lazy initialization and ServiceLoader to discover available implementations.
     * 
     * @return the cryptographic service implementation
     * @throws IllegalStateException if no implementation is available
     */
    public static ICryptoService getCryptoService() {
        if (cryptoService == null) {
            synchronized (lock) {
                if (cryptoService == null) {
                    cryptoService = loadCryptoService();
                }
            }
        }
        return cryptoService;
    }
    
    /**
     * Loads the cryptographic service using ServiceLoader.
     * 
     * @return the first available cryptographic service implementation
     * @throws IllegalStateException if no implementation is available
     */
    private static ICryptoService loadCryptoService() {
        ServiceLoader<ICryptoService> loader = ServiceLoader.load(ICryptoService.class);
        for (ICryptoService service : loader) {
            return service;
        }
        throw new IllegalStateException("No ICryptoService implementation found. " +
                "Please ensure that a cryptographic service adapter is available on the classpath.");
    }
    
    /**
     * Resets the cached cryptographic service instance.
     * This is useful for testing or when the service needs to be reloaded.
     */
    public static void reset() {
        synchronized (lock) {
            cryptoService = null;
        }
    }
} 