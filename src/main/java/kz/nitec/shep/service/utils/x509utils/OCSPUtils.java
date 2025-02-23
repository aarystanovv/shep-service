package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.asn1.*;
import kz.gov.pki.kalkan.asn1.ocsp.*;
import kz.gov.pki.kalkan.asn1.x509.AlgorithmIdentifier;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import kz.gov.pki.kalkan.util.encoders.Base64;
import kz.gov.pki.kalkan.x509.extension.AuthorityKeyIdentifierStructure;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Vector;

public class OCSPUtils
{

    static
    {
        CryptoInitializer.initCrypto();
    }

    public static final int CERTIFICATE_STATUS_OK = 0;
    public static final int CERTIFICATE_STATUS_REVOKED = 1;
    public static final int CERTIFICATE_STATUS_UNKNOWN = 2;

//    public static void main(String[] args)
//    {
//        try
//        {
//            // Данный метод добавляет JCE в окружение java.security.
//            Security.addProvider(new IolaProvider());
//            // Загружаем сертификат из файла
//            X509Certificate Cert = CertUtils.loadCertFromStream(new FileInputStream("C:\\keys_gost.p12"), "PKCS12", "123456");
//            // Формируем OCSP запрос
//            OCSPRequest req = generateRequest(Cert, "TestRequestor");
//            System.out.println(req);
//            // Отправляем запрос на сервер и получаем ответ
//            byte[] resp = sendRequest(req.getDEREncoded(), "http://ocsp.pki.kz:62223/cgi/status");
//            // Получаем статус OCSP ответа
//            int status = getOCSPStatus(resp);
//            System.out.println("Статус сертификата - " + status);
//        } catch (Exception ex)
//        {
//            ex.printStackTrace();
//        }
//    }

    public static int getCertificateStatus(X509Certificate Cert)
    {
        Configuration conf = Configuration.getInstance();
        try {
            return checkSertificateStatus(Cert, generateCert(conf.getCaGostCert()), CertificateID.HASH_GOST34311, conf.getOCSPUrl());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return CERTIFICATE_STATUS_UNKNOWN;
    }

    //Метод формирующий OCSP запрос
    private static OCSPRequest generateRequest(X509Certificate cert, String requestor)
            throws NoSuchAlgorithmException, CertificateEncodingException, IOException, CertificateParsingException
    {
        CertID certId;
        certId = buildCertId(cert);
        X509Extensions altNameExtensions = null;
        Request req = new Request(certId, altNameExtensions);
        ASN1Sequence seq = new DERSequence(new ASN1Encodable[]{req});
        GeneralName requestorName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(requestor.getBytes("ASCII")));
        X509Extensions nonceExtensions = createNonceExtensions();
        TBSRequest tbs = new TBSRequest(requestorName, seq, nonceExtensions);
        return new OCSPRequest(tbs, null);
    }

    //Метод формирующий расширение для формирования OCSP
    private static X509Extensions createNonceExtensions()
    {
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
        Vector<X509Extension> values = new Vector<X509Extension>();
        oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
        return new X509Extensions(oids, values);
    }

    //Метод формирующий CertID из сертификата
    private static CertID buildCertId(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException, IOException
    {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(new DERObjectIdentifier(cert.getSigAlgOID()), DERNull.INSTANCE);
        String issuerName = cert.getIssuerX500Principal().getName();
        byte[] issuerNameData = issuerName.getBytes("ASCII");
        ASN1OctetString issuerNameHash = new DEROctetString(issuerNameData);
        byte[] issuerKeyData = getAuthorityKeyId(cert);
        ASN1OctetString issuerKeyHash = new DEROctetString(issuerKeyData);
        DERInteger serialNumber = new DERInteger(cert.getSerialNumber());
        return new CertID(algId, issuerNameHash, issuerKeyHash, serialNumber);
    }

    //Метод формирующий идентификатор ЦС
    private static byte[] getAuthorityKeyId(X509Certificate cert)
            throws IOException
    {
        byte[] extValue = cert.getExtensionValue("2.5.29.35");
        AuthorityKeyIdentifierStructure keyId = new AuthorityKeyIdentifierStructure(extValue);
        return keyId.getKeyIdentifier();
    }

    //Метод отсылающий OCSP запрос на сервер
    private static byte[] sendRequest(byte[] req, String urlLocation) throws IOException
    {
        URL url = new URL(urlLocation);
        HttpURLConnection connection;
        connection = (HttpURLConnection) url.openConnection();
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setConnectTimeout(Integer.MAX_VALUE);
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Referer", urlLocation);
        String data = "request=" + URLEncoder.encode(new String(Base64.encode(req)), "UTF-8");
        connection.setRequestProperty("Content-Length", Integer.toString(data.length()));
        connection.connect();
        PrintWriter out = new PrintWriter(connection.getOutputStream());
        out.write(data);
        out.flush();
        BufferedReader rd = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line;
        StringBuilder result = new StringBuilder();
        while ((line = rd.readLine()) != null)
        {
            result.append(line).append("\n");
        }
        connection.disconnect();
        return Base64.decode(result.toString());
    }

    //Получение статуса проверяемого сертификата
    private static int getOCSPStatus(byte[] responce) throws IOException
    {
        ASN1InputStream respStream = new ASN1InputStream(responce);
        DERObject respObject = respStream.readObject();
        ASN1Sequence respSeq = (ASN1Sequence) respObject;
        OCSPResponse resp = new OCSPResponse(respSeq);
        BigInteger statusBig = resp.getResponseStatus().getValue();
        return statusBig.intValue();
    }

    private static int checkSertificateStatus(X509Certificate cert, X509Certificate caCert, String hash, String serviceLocation) throws Exception {
        CryptoInitializer.initCrypto();

        URL url = new URL(serviceLocation);

        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(getOcspPackage(cert.getSerialNumber(), caCert, hash));
        int ret = parseOcspResponse(con);
        con.disconnect();
        os.close();

        return ret;
    }

    private static int parseOcspResponse(HttpURLConnection con) throws Exception {
        InputStream in = con.getInputStream();
        OCSPResp response = new OCSPResp(in);
        in.close();

        if (response.getStatus() != 0) {
            throw new OCSPException("Unsuccessful request. Status: " + response.getStatus());
        }
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        X509Certificate ocspcert = brep.getCerts(KalkanProvider.PROVIDER_NAME)[0];

        SingleResp[] singleResps = brep.getResponses();
        SingleResp singleResp = singleResps[0];
        Object status = singleResp.getCertStatus();

        if (status == null) {
            return CERTIFICATE_STATUS_OK;
        }
        if (status instanceof RevokedStatus) {
            return CERTIFICATE_STATUS_REVOKED;
        }
        return CERTIFICATE_STATUS_UNKNOWN;
    }

    private static byte[] getOcspPackage(BigInteger serialNr, Certificate cacert, String hashAlg) throws Exception {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        CertificateID certId = new CertificateID(hashAlg, (X509Certificate) cacert, serialNr);
        gen.addRequest(certId);
        OCSPReq req;
        req = gen.generate();
        return req.getEncoded();
    }

    private static X509Certificate generateCert(String certFile) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").
                generateCertificate(new FileInputStream(certFile));
    }
}