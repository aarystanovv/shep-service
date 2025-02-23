package kz.nitec.shep.service.utils.x509utils;


/**
 * User: akochkin
 * Date: 06.06.11
 * Time: 11:46
 */
public class Configuration
{
    private static final String PROP_ROOT_CERTS = "rootcert.files";
    private static final String PROP_PRIVATE_KEY_FILE = "key.file";
    private static final String PROP_STORE_PWD = "key.pwd";
    private static final String PROP_CHECK_CRL = "check.crl";
    private static final String PROP_CHECK_OCSP = "check.ocsp";
    private static final String PROP_OCSP_URL = "ocsp.url";
    private static final String PROP_CA_GOST_CERT = "ca.gost.file";

    private Boolean checkCrl;
    private Boolean checkOCSP;
    private String ocspUrl;
    private String privateKeyFile;
    private String storePassword;
    private String caGostCert;

   // private Properties props = new Properties();
    private static Configuration instance;
   // private static String propFileName;
   // private long lastModificationDate;

//    static
//    {
//        //ищем файл со свойствами хранилища ключей
//        String fileName = System.getProperty("kestore.properties.file");
//        if (fileName != null)
//        {
//            propFileName = fileName;
//        } else
//        {
//            //разбираемся, мы запущены под IBM или под Tomcat
//            String root = System.getProperty("user.install.root");//IBM
//            if (root == null)
//            {
//                root = System.getProperty("catalina.home");//Tomcat
//            }
//            propFileName = root + "/certs/certificates.properties";
//        }
//    }

//    private Configuration() throws IOException
//    {
//        File f = getPropFile();
//        System.out.println("Try to load properties from " + f.getName());
//        FileInputStream stream = new FileInputStream(f);
//        props.load(stream);
//        lastModificationDate = f.lastModified();
//        stream.close();
//        System.out.println("Properties loaded from " + f.getName());
//    }

    public static Configuration getInstance()
    {
 //       File f = getPropFile();
        if (instance == null )//|| f.lastModified() != instance.lastModificationDate)
   //         try
     //       {
                instance = new Configuration();
       //     } catch (IOException e)
         //   {
           //     e.printStackTrace();
            //}
        return instance;
    }
    
//    private static File getPropFile()
//    {
//        return new File(propFileName);
//    }

    public boolean isCheckCRL()
    {
        if (checkCrl == null)
        {
            String property = getProperty(PROP_CHECK_CRL);
            checkCrl = property != null && property.trim().length() > 0 && Boolean.parseBoolean(property);
        }
        return checkCrl;
    }

    public boolean isCheckOCSP()
    {
        if (checkOCSP == null)
        {
            String property = getProperty(Configuration.PROP_CHECK_OCSP); //Configuration.getInstance().getProperty(Configuration.PROP_CHECK_OCSP);
            checkOCSP = property != null && property.trim().length() > 0 && Boolean.parseBoolean(property);
        }
        return checkOCSP;
    }

    public String getOCSPUrl()
    {
        if (ocspUrl == null)
            ocspUrl = getProperty(PROP_OCSP_URL);
        return ocspUrl;
    }

    public String getPrivateKeyFile()
    {
        if (privateKeyFile == null)
            privateKeyFile = getProperty(PROP_PRIVATE_KEY_FILE);
        return privateKeyFile;
    }

    public String getStorePassword()
    {
        if (storePassword == null)
            storePassword = getProperty(PROP_STORE_PWD);
        return storePassword;
    }

    public String[] getRootCertFiles()
    {
        return getProperty(PROP_ROOT_CERTS).split(",");
    }

    public String getCaGostCert() {
        if (caGostCert == null) {
            caGostCert = getProperty(PROP_CA_GOST_CERT);
        }
        return caGostCert;
    }

    public String getCertificateFile(String keyAlias)
    {
        return getProperty((keyAlias + ".store.file"));
    }

    public String getPrivateKeyFile(String keyAlias)
    {
        return getProperty(keyAlias + "." + PROP_PRIVATE_KEY_FILE);
    }

    public String getPrivateKeyPassword(String keyAlias)
    {
        return getProperty(keyAlias + "." + PROP_STORE_PWD);
    }

    private String getProperty(String name)
    {
        return System.getProperty(name);//props.getProperty(name);
    }
}
