package org.openpdf.text.pdf.crypto;

import java.util.ServiceLoader;

public class CryptoServiceProvider {
    private static final ICryptoService INSTANCE = loadService();

    private static ICryptoService loadService() {
        ServiceLoader<ICryptoService> loader = ServiceLoader.load(ICryptoService.class);
        for (ICryptoService service : loader) {
            return service;
        }
        throw new IllegalStateException("No ICryptoService implementation found on classpath");
    }

    public static ICryptoService get() {
        return INSTANCE;
    }
} 