package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import sun.misc.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Взято из SDK Гамма
 *
 * @author smirnov_v
 */
public class FileSystemFunctions
{

    /**
     * Загрузка данных из файла
     *
     * @param fileName Имя файла
     * @return Путь к домашней директории пользователя
     */
    public static byte[] readData(final String fileName)
    {
        FileInputStream fis = null;
        try
        {
            fis = new FileInputStream(fileName);
            int size = fis.available();
            byte[] result = new byte[size];
            fis.read(result, 0, size);
            return result;
        } catch (FileNotFoundException e)
        {
            throw new RuntimeException(e);
        } catch (IOException e)
        {
            throw new RuntimeException(e);
        } finally
        {
            if (fis != null)
            {
                try
                {
                    fis.close();
                } catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        }
    }

    // Метод загружает сертификат из файла c ключевым контейнером
    // Поддерживаются 2 типа ключевых контенеров BKS и PKCS12
    public static X509Certificate loadCertFromFile(String fileName, String fileType, String pass)
    {
        X509Certificate cert = null;
        KeyStore store;
        byte[] buf;
        try
        {


            URL resource = FileSystemFunctions.class.getClassLoader().getResource(fileName);

            File file = new File(resource.toURI());
            FileInputStream f = new FileInputStream(file);
            buf = new byte[f.available()];
            f.read(buf, 0, f.available());

            //Указываем классу KeyStore что необходимо использовать JCE GAMMA.
            store = KeyStore.getInstance(fileType, KalkanProvider.PROVIDER_NAME);
            store.load(new ByteArrayInputStream(buf), pass.toCharArray());
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

    // Метод загружает закрытый ключь из файла c ключевым контейнером
    // Поддерживаются 2 типа ключевых контенеров BKS и PKCS12
    public static PrivateKey loadKeyFromFile(String fileName, String fileType, String pass)
    {
        PrivateKey privKey = null;
        KeyStore store;
        byte[] buf;
        try
        {
            URL resource = FileSystemFunctions.class.getClassLoader().getResource(fileName);

            File file = new File(resource.toURI());
            FileInputStream f = new FileInputStream(file);
            buf = new byte[f.available()];
            f.read(buf, 0, f.available());
            //Указываем классу KeyStore что необходимо использовать JCE GAMMA.
            store = KeyStore.getInstance(fileType, KalkanProvider.PROVIDER_NAME);
            store.load(new ByteArrayInputStream(buf), pass.toCharArray());
            Enumeration en = store.aliases();
            String alias = null;
            //В данном цикле для получения ключа используется последний alias.
            while (en.hasMoreElements()) alias = en.nextElement().toString();
            privKey = (PrivateKey) store.getKey(alias, pass.toCharArray());
        } catch (Exception ex)
        {
            ex.printStackTrace();
        }
        return privKey;
    }
}
