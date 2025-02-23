package kz.nitec.shep.service.utils.xmlds;

import kz.nitec.shep.service.utils.x509utils.*;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.GregorianCalendar;

public class XmlDsUtils {
    static {
        CryptoInitializer.initCrypto();
    }

    // Метод формирования подписи xml документа

    public static String signXML(String xml, X509Certificate cert,
                                 PrivateKey privKey) throws Exception {
        return signXML(parseDocument(xml), cert, privKey);
    }

    // Метод формирования подписи xml документа

    public static String signXML(Document doc, X509Certificate cert,
                                 PrivateKey privKey) throws Exception {
        StringWriter os = null;
        String signMethod;
        String digestMethod;
        if ("RSA".equals(privKey.getAlgorithm())) {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#sha1";
        } else {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        }
        XMLSignature sig = new XMLSignature(doc, "", signMethod);
        String res = "";
        try {
            if (doc.getFirstChild() != null) {
                doc.getFirstChild().appendChild(sig.getElement());
                Transforms transforms = new Transforms(doc);
                transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
                transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
                sig.addDocument("", transforms, digestMethod);
                sig.addKeyInfo(cert);
                sig.sign(privKey);
                os = new StringWriter();
                TransformerFactory tf = TransformerFactory.newInstance();
                Transformer trans = tf.newTransformer();
                trans.transform(new DOMSource(doc), new StreamResult(os));
                os.flush();
                res = os.toString();
                os.close();
            }
            return res;
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Метод подписания SOAP-сообщения. В заголовке (SOAPHeader) создаётся элемент ds:Signature,
     * с подписью, ссылающейся на тело сообщения (SOAPBody). В теле создаётся атрибут ID с
     * предопределённым значением, на который и ссылается подпись.
     *
     * @param message SOAP-сообщение
     * @param cert    сертификат
     * @param privKey закрытый ключ
     * @throws Exception в случае ошибок
     */
    public static void signSOAP(SOAPMessage message, X509Certificate cert,
                                PrivateKey privKey) throws Exception {
        if (message.getSOAPHeader() == null) {
            message.getSOAPPart().getEnvelope().addHeader();
        }
        String bodyId = "id-body";
        Document body = XMLUtils.getOwnerDocument(message.getSOAPBody());
        Document header = XMLUtils.getOwnerDocument(message.getSOAPHeader());
        Attr id = body.createAttributeNS(null, "id");
        id.setValue(bodyId);
        message.getSOAPBody().setAttributeNodeNS(id);

        String signMethod;
        String digestMethod;
        if ("RSA".equals(privKey.getAlgorithm())) {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#sha1";
        } else {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        }
        XMLSignature sig = new XMLSignature(body, "", signMethod);
        Transforms transforms = new Transforms(header);
        transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
        sig.addDocument("#" + bodyId, transforms, digestMethod);
        sig.addKeyInfo(cert);
        message.getSOAPHeader().appendChild(sig.getElement());
        sig.sign(privKey);
    }

    /**
     * Метод подписания SOAP-сообщения. В заголовке (SOAPHeader) создаётся элемент
     * ds:Signature, с подписью, ссылающейся на элемент, с указанным идентификатором.
     *
     * @param message SOAP-сообщение
     * @param cert    сертификат
     * @param privKey закрытый ключ
     * @param elementToSignId    идентификатор DOM-элемента, который требуется подписать
     * @throws Exception в случае ошибок
     */
    public static void signSOAP(SOAPMessage message, X509Certificate cert,
                                PrivateKey privKey, String elementToSignId) throws Exception {
        if (message.getSOAPHeader() == null) {
            message.getSOAPPart().getEnvelope().addHeader();
        }
        Document body = XMLUtils.getOwnerDocument(message.getSOAPBody());
        Document header = XMLUtils.getOwnerDocument(message.getSOAPHeader());

        String signMethod;
        String digestMethod;
        if ("RSA".equals(privKey.getAlgorithm())) {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#sha1";
        } else {
            signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
            digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        }
        XMLSignature sig = new XMLSignature(body, "", signMethod);
        Transforms transforms = new Transforms(header);
        transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
        sig.addDocument("#" + elementToSignId, transforms, digestMethod);
        sig.addKeyInfo(cert);
        message.getSOAPHeader().appendChild(sig.getElement());
        sig.sign(privKey);
    }

    /**
     * Перед передачей проверки методу {@link #validateXMLSignature(Document)}
     * осуществляется проверка - подпись должна удостоверять элемент Body.
     *
     * @param message SOAP-сообщение
     * @return результат проверки
     */
    public static VerificationData validateSOAPSignature(SOAPMessage message) {
        try {
            Element nscontext = XMLUtils.createDSctx(message.getSOAPHeader().getOwnerDocument(), "ds", "http://www.w3.org/2000/09/xmldsig#");
            NodeList list = XPathAPI.selectNodeList(message.getSOAPHeader(), "//ds:Reference", nscontext);
            if (list.getLength() < 1) {
                System.err.println("Bad signature: Element 'ds:Reference' is not found in SOAPHeader");
                return new VerificationData(VerificationResult.CORRUPTED_XML, null, null);
            }
/* по мере развития различных систем, появляются требования подписывать части сообщений,
не являющиеся элементами Body, поэтому убрал эту проверку
            String id = list.item(0).getAttributes().getNamedItem("URI").getNodeValue().substring(1);
            if (!id.equals( findId(message.getSOAPBody()))) {
                System.err.println("Bad signature: Element 'ds:Reference' must be a reference to element Body");
                return new VerificationData(VerificationResult.FAILURE_BAD_SIGNATURE, null, null);
            }
*/
            //проверяем только последнюю подпись, т.к. при использовании метода ENVELOPED
            //валидной является только последняя подпись. Чтобы проверить предыдущую подпись,
            //из документа следует удалить последнюю
            list = XPathAPI.selectNodeList(message.getSOAPHeader(), "//ds:Signature", nscontext);
            Element sigElement = (Element) list.item(list.getLength() - 1);
            XMLSignature signature = new XMLSignature(sigElement, "");
            return validateXMLSignature(signature, null);
        } catch (Exception e) {
            e.printStackTrace();
            return new VerificationData(VerificationResult.FAILURE_UNKNOWN, null, null);
        }
    }

    /*
    Проблема в том, что имя атрибута может быть в разном регистре, поэтому getAttribute("id")
    срабатывает не всегда. Данный метод осуществляет поиск вне зависимости от регистра
     */
/*
    private static String findId( SOAPBody body) {
        NamedNodeMap map = body.getAttributes();
        for (int i = 0; i < map.getLength(); i++) {
            Node item = map.item(i);
            if (item.getNodeName().toLowerCase().equals("id")) {
                return item.getNodeValue();
            }
        }
        return "";
    }
*/

    /**
     * Метод проверки подписи xml документа на текущий момент времени. Проверяется только последняя подпись в списке
     * подписей документа.
     *
     * @param doc проверяемый документ
     *            Online Certificate Status Protocol; альтернатива проверке путем сверки с СОС
     * @return результат проверки
     */
    public static VerificationResult validateXMLSignature(Document doc) {
        return validateXMLSignature(doc, null);
    }

    /**
     * Проверка подписи XML документа на заданный момент времени.  Проверяется только последняя подпись в списке
     * подписей документа.
     *
     * @param doc проверяемый документ
     *            Online Certificate Status Protocol; альтернатива проверке путем сверки с СОС
     * @param date дата, на которую необходимо проверить подпись. В случае если date=null, то проверка производится на
     * текущий момент. Так же в этом случае производится проверка на отозванность в соответствии с файлом конфигурации.
     * Если date != null, то проверка на отозванность не производится, т.к. из CRL/OCSP не возможно определить когда
     * именно был отозван сертификат. А если срок действия сертификата на текущий момент истек, то в CRL/OCSP этого
     * сертификата вообще не будет
     * @return результат проверки
     */
    public static VerificationResult validateXMLSignature(Document doc, Date date) {
        try {
            Element nscontext = XMLUtils.createDSctx(doc, "ds", "http://www.w3.org/2000/09/xmldsig#");
            //проверяем только последнюю подпись, т.к. при использовании метода ENVELOPED
            //валидной является только последняя подпись. Чтобы проверить предыдущую подпись,
            //из документа следует удалить последнюю
            NodeList list = XPathAPI.selectNodeList(doc, "//ds:Signature", nscontext);
            Element sigElement = (Element) list.item(list.getLength() - 1);
            XMLSignature signature = new XMLSignature(sigElement, "");
            return validateXMLSignature(signature, date).getVerificationResult();
        } catch (TransformerException e) {
            e.printStackTrace();
            return VerificationResult.FAILURE_UNKNOWN;
        } catch (XMLSignatureException e) {
            e.printStackTrace();
            return VerificationResult.CORRUPTED_CERT;
        } catch (XMLSecurityException e) {
            e.printStackTrace();
            return VerificationResult.CORRUPTED_CERT;
        }
    }
    /**
     * Метод проверки подписей xml документа. Проверяются все подписи в списке
     * подписей документа.
     *
     * @param xml проверяемый документ
     *            Online Certificate Status Protocol; альтернатива проверке путем сверки с СОС
     * @return результат проверки - соответствует количеству подписей
     * @throws TransformerException структура XML не распознана
     * @throws XMLSecurityException структура XML не распознана
     */
    public static VerificationData[] validateXMLSignatures(String xml)
            throws TransformerException, XMLSecurityException, IOException, SAXException, ParserConfigurationException {
        return validateXMLSignatures(parseDocument(xml));
    }

    public static VerificationData[] validateXMLSignatures(String xml, Date date)
            throws TransformerException, XMLSecurityException, IOException, SAXException, ParserConfigurationException {
        return validateXMLSignatures(parseDocument(xml), date);
    }

    /**
     * Метод проверки подписей xml документа. Проверяются все подписи в списке
     * подписей документа.
     *
     * @param doc проверяемый документ
     *            Online Certificate Status Protocol; альтернатива проверке путем сверки с СОС
     * @return результат проверки - соответствует количеству подписей
     * @throws TransformerException структура XML не распознана
     * @throws XMLSecurityException структура XML не распознана
     */
    public static VerificationData[] validateXMLSignatures(Document doc) throws TransformerException, XMLSecurityException {
        return validateXMLSignatures(doc, null);
    }

    public static VerificationData[] validateXMLSignatures(Document doc, Date date) throws TransformerException, XMLSecurityException {
        Element nscontext = XMLUtils.createDSctx(doc, "ds", "http://www.w3.org/2000/09/xmldsig#");
        NodeList list = XPathAPI.selectNodeList(doc, "//ds:Signature", nscontext);
        VerificationData[] result = new VerificationData[list.getLength()];
        //проверяем последовательно все подписи. Чтобы проверить предыдущую подпись,
        //из документа следует удалить последнюю
        for (int i = list.getLength() - 1; i >= 0; i--) {
            Element element = (Element) list.item(i);
            XMLSignature signature = new XMLSignature(element, "");
            //checkCrl признак - проверять ли по Списку Отозванных Сертификатов
            //checkOCSP признак - проверять ли статус отозванности при помощи
            result[i] = validateXMLSignature(signature, date);
            element.getParentNode().removeChild(element);
        }
        return result;
    }

    private static VerificationData validateXMLSignature(XMLSignature signature, Date date) {
        String subjectDN = null;
        X509Certificate certKey = null;
        try {
            org.apache.xml.security.keys.KeyInfo ki = signature.getKeyInfo();
            certKey = ki.getX509Certificate();
            subjectDN = certKey != null && certKey.getSubjectDN() != null
                    ? certKey.getSubjectDN().toString() : null;
            VerificationResult result = VerificationResult.SUCCESS;

            if (certKey != null) {
                if (!signature.checkSignatureValue(certKey))
                    result = VerificationResult.FAILURE_BAD_SIGNATURE;
            } else {
                PublicKey pk = ki.getPublicKey();

                if (pk != null) {
                    if (!signature.checkSignatureValue(pk))
                        result = VerificationResult.FAILURE_BAD_SIGNATURE;
                } else
                    result = VerificationResult.CORRUPTED_CERT;
            }

            if (result.equals(VerificationResult.SUCCESS)) {
                boolean checkCrl = Configuration.getInstance().isCheckCRL();
                boolean checkOCSP = Configuration.getInstance().isCheckOCSP();

                result = CertUtils.verifyCertificate(certKey, checkCrl, checkOCSP, date);
            }
            return new VerificationData(result, subjectDN, certKey);
        } catch (XMLSignatureException e) {
            e.printStackTrace();
            return new VerificationData(VerificationResult.CORRUPTED_CERT, subjectDN, certKey);
        } catch (XMLSecurityException e) {
            e.printStackTrace();
            return new VerificationData(VerificationResult.CORRUPTED_CERT, subjectDN, certKey);
        }
    }

    private static Document parseDocument(String xml)
            throws IOException, ParserConfigurationException, SAXException {
        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes("UTF-8"));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        return documentBuilder.parse(bais);
    }
    //преобразовать Date в XMLGregorianCalendar
    public static XMLGregorianCalendar dateToCalendar(Date date) {
        if(date == null) return null;
        GregorianCalendar gCalendar = new GregorianCalendar();
        gCalendar.setTime(date);
        XMLGregorianCalendar xmlCalendar = null;
        try {
            xmlCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(gCalendar);
        }catch (DatatypeConfigurationException e){
            e.printStackTrace();
        }
        return xmlCalendar;
    }
}