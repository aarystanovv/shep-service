package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Enumeration;


public class CertUtils
{

    private static KeyStoreLoader keyStoreLoader;

    static
    {
        CryptoInitializer.initCrypto();
    }

    public static KeyStoreLoader getKeyStore() throws IOException, NoSuchProviderException,
            NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {
        if (keyStoreLoader == null)
        {
            keyStoreLoader = new KeyStoreLoader();
        }
        return keyStoreLoader;
    }

    // Метод загружает сертификат из файла
    public static X509Certificate loadCertFromStream(InputStream input)
    {
        X509Certificate cert = null;
        try
        {
            // Указываем классу CertificateFactory что необходимо использовать JCE GAMMA.
            CertificateFactory cf = CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME);
            cert = (X509Certificate) cf.generateCertificate(input);
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return cert;
    }

    // Метод загружает закрытый ключь из файла c ключевым контейнером
    // Поддерживаются 2 типа ключевых контенеров BKS и PKCS12
    public static PrivateKey loadKeyFromStream(InputStream input, String storeType, String pass)
    {
        PrivateKey privKey = null;
        try
        {
            //Указываем классу KeyStore что необходимо использовать JCE GAMMA.            
            KeyStore store = KeyStore.getInstance(storeType, KalkanProvider.PROVIDER_NAME);
            store.load(input, pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            //В данном цикле для получения ключа используется последний alias.
            while (en.hasMoreElements())
                alias = en.nextElement().toString();
            privKey = (PrivateKey) store.getKey(alias, pass.toCharArray());
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return privKey;
    }

    // Метод загружает сертификат из файла c ключевым контейнером
    // Поддерживаются 2 типа ключевых контенеров BKS и PKCS12
    public static X509Certificate loadCertFromStream(InputStream input, String storeType, String pass)
    {
        X509Certificate cert = null;
        try
        {
            //Указываем классу KeyStore что необходимо использовать JCE GAMMA.
            KeyStore store = KeyStore.getInstance(storeType, KalkanProvider.PROVIDER_NAME);
            store.load(input, pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            //В данном цикле для получения ключа используется последний alias.
            while (en.hasMoreElements()) alias = en.nextElement().toString();
            cert = (X509Certificate) store.getCertificateChain(alias)[0];
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return cert;
    }

    /**
     * Проверка валидности сертификата на указанный момент времени. Если date != null, то проверка по CRL/OCSP
     * не проводится, т.к. не возможно определить был ли отозван сертификат на указанный момент времени.
     *
     * @param certificate сертификат на проверку
     * @param checkCrl    проверять ли по CRL
     * @param checkOCSP   проверять ли по OCSP
     * @param date        дата, на которую надо проверить сертификатю Если date = null, то проверка осуществляется на
     *                    текущий момент времени.
     * @return результат проверки сертификата
     */
    public static VerificationResult verifyCertificate(X509Certificate certificate, boolean checkCrl, boolean checkOCSP,
                                                       Date date)
    {
        if (certificate == null)
            throw new IllegalArgumentException("chainCerts is null");
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME);

            certificate.checkValidity(date == null ? new Date() : date);
            PublicKey pk = getKeyStore().getRootPublicKey(certificate);
            if (pk == null)
                throw new SignatureException();
            certificate.verify(pk);

            if (checkCrl && (date == null || (new Date().getTime()-date.getTime() < 1000L*60*60*24)))
            {
                CrlUtils crlManager = new CrlUtils(cf);
                crlManager.verifyCertInCRL(certificate);
            }

            VerificationResult result = VerificationResult.SUCCESS;

            if (checkOCSP && (date == null || (new Date().getTime()-date.getTime() < 1000L*60*60*24)))
            {
                int ocspResult = OCSPUtils.getCertificateStatus(certificate);
                if (ocspResult == OCSPUtils.CERTIFICATE_STATUS_REVOKED)
                    result = VerificationResult.FAILURE_REVOCED;
                if (ocspResult == OCSPUtils.CERTIFICATE_STATUS_UNKNOWN)
                    result = VerificationResult.FAILURE_UNKNOWN;
            }
            return result;
        } catch (CRLException e)
        {
//            e.printStackTrace();
            return VerificationResult.FAILURE_REVOCED;
        } catch (CertificateExpiredException e)
        {
//            e.printStackTrace();
            return VerificationResult.FAILURE_EXPIRED;
        } catch (CertificateNotYetValidException e)
        {
//            e.printStackTrace();
            return VerificationResult.FAILURE_NOT_YET_VALID;
        } catch (CertificateException e)
        {
//            e.printStackTrace();
            return VerificationResult.CORRUPTED_CERT;
        } catch (SignatureException e)
        {
//            e.printStackTrace();
            return VerificationResult.FAILURE_CHAIN_INVALID;
        } catch (Exception e)
        {
            e.printStackTrace();
        }
        return VerificationResult.FAILURE_UNKNOWN;
    }

    /**
     * Проверка, является ли оба объекта одним и тем же сертификатом. Сверяется серийный
     * номер сертификатов
     *
     * @param cert1 один из сертификатов
     * @param cert2 другой сертификат
     * @return признак, один и тот же сертификат или нет
     */
    public static boolean isSame(X509Certificate cert1, X509Certificate cert2)
    {
        return !(cert1 == null || cert2 == null)
                && cert1.getSerialNumber().equals(cert2.getSerialNumber());
    }
}