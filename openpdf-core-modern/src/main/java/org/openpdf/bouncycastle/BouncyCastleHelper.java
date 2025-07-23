package org.openpdf.bouncycastle;

import org.openpdf.text.ExceptionConverter;
import org.openpdf.text.pdf.PdfArray;
import org.openpdf.text.pdf.PdfObject;
import org.openpdf.text.pdf.crypto.CryptoServiceProvider;
import java.security.Key;
import java.security.cert.Certificate;
import java.util.List;

public class BouncyCastleHelper {

    public static void checkCertificateEncodingOrThrowException(Certificate certificate) {
        try {
            CryptoServiceProvider.get().checkCertificateEncoding(certificate);
        } catch (Exception f) {
            throw new ExceptionConverter(f);
        }
    }

    @SuppressWarnings("unchecked")
    public static byte[] getEnvelopedData(PdfArray recipients, List<PdfObject> strings, Certificate certificate,
            Key certificateKey, String certificateKeyProvider) {
        byte[] envelopedData = null;
        for (PdfObject recipient : recipients.getElements()) {
            strings.remove(recipient);
            try {
                envelopedData = CryptoServiceProvider.get().extractEnvelopedData(
                    recipient.getBytes(), (java.security.PrivateKey)certificateKey, certificate);
                if (envelopedData != null) {
                    break;
                }
            } catch (Exception f) {
                throw new ExceptionConverter(f);
            }
        }
        return envelopedData;
    }
}
