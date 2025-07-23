package org.openpdf.text.pdf.crypto;

import java.util.ServiceLoader;

public class CryptoServiceProvider {
    private static volatile ICryptoService INSTANCE;

    private static ICryptoService loadService() {
        ServiceLoader<ICryptoService> loader = ServiceLoader.load(ICryptoService.class);
        for (ICryptoService service : loader) {
            return service;
        }
        throw new IllegalStateException("No ICryptoService implementation found on classpath");
    }

    public static ICryptoService get() {
        if (INSTANCE == null) {
            synchronized (CryptoServiceProvider.class) {
                if (INSTANCE == null) {
                    INSTANCE = loadService();
                }
            }
        }
        return INSTANCE;
    }
} 