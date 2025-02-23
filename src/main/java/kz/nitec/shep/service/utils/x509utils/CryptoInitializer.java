package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;

import java.security.Security;

/**
 * User: akochkin
 * Date: 06.06.11
 * Time: 11:58
 */
public class CryptoInitializer
{
    private static boolean initialized = false;

    public static void initCrypto() {
        if (!initialized) {
            if (Security.getProvider(KalkanProvider.PROVIDER_NAME) != null) {
                Security.removeProvider(KalkanProvider.PROVIDER_NAME);
            }
            KalkanProvider kalkanProvider = new KalkanProvider();
            Security.addProvider(kalkanProvider);
            KncaXS.loadXMLSecurity();
            initialized = true;
        }
    }
    
}