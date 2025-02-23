package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.asn1.x509.AuthorityKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.SubjectKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.util.ByteUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * В корневой папке профайла сервера должна быть папка certs, содержащая
 * файлы certificates.properties, и два контейнера - ключи для подписания и корневой сертификат
 * УЦ. В certificates.properties указаны имена файлов контейнеров и пароль к контейнру с ключом.
 * Также путь к properties-файлу может быть указан путём задания свойства
 * System.setProperty( "kestore.properties.file", "путь/к/файлу/имя-файла")
 * <p/>
 * Created by IntelliJ IDEA. User: smirnov_v Date: 14.07.2010
 */
public class KeyStoreLoader
{
    private static final String DEFAULT_PASSWORD = "123456";

    private PrivateKey systemPrivateKey;
    private X509Certificate systemCert;
    private Map<String, PublicKey> keyCache;

    private static Map<String, X509Certificate> certificates = new HashMap<String, X509Certificate>();
    private static Map<String, PrivateKey> privateKeys = new HashMap<String, PrivateKey>();

    static
    {
        CryptoInitializer.initCrypto();
    }

    public PrivateKey getSystemPrivateKey() throws Exception
    {
        if (systemPrivateKey == null) {
            initSystemKey();
        }
        return systemPrivateKey;
    }

    public X509Certificate getSystemCert() throws Exception
    {
        if (systemCert == null) {
            initSystemKey();
        }
        return systemCert;
    }

    public void initSystemKey() throws KeyStoreException {
        String pwd = Configuration.getInstance().getStorePassword();
        if (pwd == null || pwd.trim().length() == 0)
            pwd = DEFAULT_PASSWORD;//даём возможнось не указывать пароль в открытом .properties-файле
        systemPrivateKey = FileSystemFunctions.loadKeyFromFile(
                Configuration.getInstance().getPrivateKeyFile(), "PKCS12", pwd);
        if (systemPrivateKey == null)
        {
            throw new KeyStoreException("There is no keys found in Key Store [" + Configuration.getInstance().getPrivateKeyFile() + "]");
        }
        systemCert = FileSystemFunctions.loadCertFromFile(
                Configuration.getInstance().getPrivateKeyFile(), "PKCS12", pwd);
        if (systemCert == null)
        {
            throw new KeyStoreException("There is no certificate found in Key Store [" + Configuration.getInstance().getPrivateKeyFile() + "]");
        }
    }

    /**
     * @return публичный ключ рутового сертификата запрашиваемого алгоритма подписи
     * @throws IOException
     */
    public PublicKey getRootPublicKey(X509Certificate certificate) throws IOException, NoSuchProviderException, CertificateException {
        if (keyCache == null) {
            initRootPublicKeys();
        }
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier
                .getInstance(CSPUtils.getExtensionValue(certificate, X509Extensions.AuthorityKeyIdentifier.getId()));
        String keyIdentifier = ByteUtils.array2hex(aki.getKeyIdentifier());
        return keyCache.get(keyIdentifier);
    }

    public void initRootPublicKeys() throws NoSuchProviderException, CertificateException, IOException
    {
        keyCache = new HashMap<String, PublicKey>();
        String[] roots = Configuration.getInstance().getRootCertFiles();
        for (String file : roots)
        {
            byte[] rootBytes = FileSystemFunctions.readData(file);
            X509Certificate rootCert = (X509Certificate) CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME)
                    .generateCertificate(new ByteArrayInputStream(rootBytes));
            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(CSPUtils.getExtensionValue(rootCert, X509Extensions.SubjectKeyIdentifier.getId()));
            String keyIdentifier = ByteUtils.array2hex(ski.getKeyIdentifier());
            keyCache.put(keyIdentifier, rootCert.getPublicKey());
        }
    }

    /**
     * Получить сертификат из файлового хранилища, с сохранением во
     * внутреннем кэше
     *
     * @param key ключ для поиска свойства в properties-файле
     * @return закрытый ключ и сертификат
     * @throws IOException       в случае ошибки загрузки из хранилища
     * @throws KeyStoreException в случае отсутствия ключа либо сертификата в хранилище
     * @throws NoSuchProviderException
     *                           GAMMA не загружен
     * @throws CertificateException
     *                           ошибка сертификата
     */
    public static X509Certificate getKeyCertificate(String key)
            throws IOException, KeyStoreException, NoSuchProviderException, CertificateException
    {
        X509Certificate certificate = certificates.get(key);
        if (certificate == null)
        {
            byte[] rootBytes = FileSystemFunctions.readData(Configuration.getInstance().getCertificateFile(key));
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME).
                    generateCertificate(new ByteArrayInputStream(rootBytes));
            if (certificate == null)
            {
                throw new KeyStoreException("No certificate founded in Key Store [" + key + "]");
            }
            certificates.put(key, certificate);
        }
        return certificate;
    }

    /**
     * Получить закрытый ключ из файлового хранилища, с сохранением во
     * внутреннем кэше
     *
     * @param property код (XXX), по которому из файла свойств берётся путь к файлу хранилища ключа
     *                 и пароль к хранилищу (XXX.key.file и XXX.key.pwd)
     * @return закрытый ключ
     * @throws Exception в случае невозможности получить ключ из хранилища
     */
    public static PrivateKey getPrivateKey(String property) throws Exception
    {
        PrivateKey privateKey = privateKeys.get(property);
        if (privateKey == null)
        {
            privateKey = FileSystemFunctions.loadKeyFromFile(
                    Configuration.getInstance().getPrivateKeyFile(property), "PKCS12",
                    Configuration.getInstance().getPrivateKeyPassword(property));
            if (privateKey == null)
            {
                throw new KeyStoreException("No PrivateKey founded in Key Store. Property name [" + property + "]");
            }
            privateKeys.put(property, privateKey);
        }
        return privateKey;
    }
}
