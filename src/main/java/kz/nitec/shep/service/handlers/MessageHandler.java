package kz.nitec.shep.service.handlers;

import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import kz.nitec.shep.service.utils.x509utils.FileSystemFunctions;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.xml.security.c14n.Canonicalizer;

import org.apache.xml.security.encryption.XMLCipherParameters;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public class MessageHandler implements SOAPHandler<SOAPMessageContext> {
//    private static final String SHEP_CERT_FILE = "certs/shep_cert.cer";
    private static final String SHEP_CERT_FILE = "keys/GOSTKNCA_9b4f6827a2736acff3de3948392286d61e13a91c.cer";
    private static final String KEY_PATH = "keys/GOSTKNCA_9b4f6827a2736acff3de3948392286d61e13a91c.p12";
    private static final String KEY_PASS = "Qwerty12";

    public static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    public static final String WSU_PREFIX = "wsu";

    @Override
    public Set<QName> getHeaders() {
        QName qName = new QName("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd","Security");
        HashSet<QName> hashSet = new HashSet<>();
        hashSet.add(qName);
        return hashSet;
    }

    @Override
    public boolean handleMessage(SOAPMessageContext context) {
        System.out.println("-------------handleMessage-------------");
        Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        SOAPMessageContext soapMessageContext = (SOAPMessageContext) context;
        SOAPMessage soapMessage = soapMessageContext.getMessage();


        ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
        try {
            soapMessage.writeTo(arrayOutputStream);
            String xml = new String(arrayOutputStream.toByteArray());

            if (outboundProperty.booleanValue()) {
                System.out.println("Sign soap");
                SOAPMessage signedSoap = sign(xml);
                context.getMessage().getSOAPPart().setContent(signedSoap.getSOAPPart().getContent());

                ByteArrayOutputStream arrayOutputStream1 = new ByteArrayOutputStream();
                signedSoap.writeTo(arrayOutputStream1);
                System.out.println(new String(arrayOutputStream1.toByteArray()));
                return true;
            } else {
                if (!xml.contains("wsse:Security")) {
                    System.out.println("Отсутствует транспортная ЭЦП");
                    SOAPMessage message = getErrorSoap(xml,"SIGN_NOT_EXIST");
                    soapMessage.getSOAPPart().setContent(message.getSOAPPart().getContent());
                } else {
                    System.out.println("Имеется транспортная ЭЦП");
                    if (verifyXml(xml, getCertificate())) {
                        SOAPMessage message = getSoapWithoutSign(xml);
                        soapMessage.getSOAPPart().setContent(message.getSOAPPart().getContent());
                    } else {
                        System.out.println("ЭЦП отрицательная");
                        SOAPMessage message = getErrorSoap(xml,"IS_NOT_VALID");
                        soapMessage.getSOAPPart().setContent(message.getSOAPPart().getContent());
                    }
                }
            }
        } catch (SOAPException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {

        }
        return true;
    }

    @Override
    public boolean handleFault(SOAPMessageContext context) {
        return false;
    }

    @Override
    public void close(MessageContext context) {
        System.out.println("On Close handler");
    }

    public boolean verifyXml(String xmlString, X509Certificate x509Certificate) {
        KalkanProvider kalkanProvider = new KalkanProvider();
        Security.addProvider(kalkanProvider);
        KncaXS.loadXMLSecurity();

        InputStream inStream = null;
        X509Certificate cert = null;
        boolean result = false;
        try {
            inStream = getClass().getClassLoader().getResourceAsStream(SHEP_CERT_FILE);

            CertificateFactory cf = CertificateFactory.getInstance("X.509", kalkanProvider.getName());
            cert = (X509Certificate) cf.generateCertificate(inStream);
            System.out.println("dn: " + cert.getIssuerDN().toString());
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));

            Element sigElement = null;
            Element rootEl = (Element) doc.getFirstChild();
            NodeList list = rootEl.getElementsByTagName("ds:Signature");
            int length = list.getLength();
            System.out.println(length);
            for (int i = 0; i < length; i++) {
                Node sigNode = list.item(length - 1);
                sigElement = (Element) sigNode;
                if (sigElement == null) {
                    System.err.println("Bad signature: Element 'ds:Reference' is not found in XML document");
                }
                XMLSignature signature = new XMLSignature(sigElement, "");
                result = signature.checkSignatureValue(cert);

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("VERIFICATION RESULT IS: " + result);
        return result;
    }

    public SOAPMessage sign(final String SIMPLE_XML_SOAP) {
        KalkanProvider kalkanProvider = new KalkanProvider();
        Security.addProvider(kalkanProvider);
        KncaXS.loadXMLSecurity();

        final String signMethod;
        final String digestMethod;
        InputStream is = new ByteArrayInputStream(SIMPLE_XML_SOAP.getBytes());
        try {
            SOAPMessage msg = MessageFactory.newInstance().createMessage(null, is);

            SOAPEnvelope env = msg.getSOAPPart().getEnvelope();
            SOAPBody body = env.getBody();

            String bodyId = "id-" + UUID.randomUUID().toString();
            body.addAttribute(new QName(WSU_NS, "Id", WSU_PREFIX), bodyId);

            SOAPHeader header = env.getHeader();
            if (header == null) {
                header = env.addHeader();
            }

            InputStream inStream = getClass().getClassLoader().getResourceAsStream(SHEP_CERT_FILE);
            final PrivateKey privateKey = FileSystemFunctions.loadKeyFromFile(KEY_PATH,"PKCS12", KEY_PASS);
            final X509Certificate x509Certificate = FileSystemFunctions.loadCertFromFile(KEY_PATH,"PKCS12", KEY_PASS);

            String sigAlgOid = x509Certificate.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha1";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "sha1";
            } else if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = Constants.MoreAlgorithmsSpecNS + "rsa-sha256";
                digestMethod = XMLCipherParameters.SHA256;
            } else {
                signMethod = Constants.MoreAlgorithmsSpecNS + "gost34310-gost34311";
                digestMethod = Constants.MoreAlgorithmsSpecNS + "gost34311";
            }

            Document doc = env.getOwnerDocument();
            Transforms transforms = new Transforms(env.getOwnerDocument());
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            Element c14nMethod = XMLUtils.createElementInSignatureSpace(doc, "CanonicalizationMethod");
            c14nMethod.setAttributeNS(null, "Algorithm", Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            Element signatureMethod = XMLUtils.createElementInSignatureSpace(doc, "SignatureMethod");
            signatureMethod.setAttributeNS(null, "Algorithm", signMethod);

            XMLSignature sig = new XMLSignature(env.getOwnerDocument(), "", signatureMethod, c14nMethod);

            sig.addDocument("#" + bodyId, transforms, digestMethod);
            sig.getSignedInfo().getSignatureMethodElement().setNodeValue(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            WSSecHeader secHeader = new WSSecHeader();
            secHeader.setMustUnderstand(true);
            secHeader.insertSecurityHeader(env.getOwnerDocument());
            secHeader.getSecurityHeader().appendChild(sig.getElement());
            header.appendChild(secHeader.getSecurityHeader());

            SecurityTokenReference reference = new SecurityTokenReference(doc);
            reference.setKeyIdentifier(x509Certificate);

            sig.getKeyInfo().addUnknownElement(reference.getElement());
            sig.sign(privateKey);

            String signedSoap = org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);

            SOAPMessage soapMessage = createSOAPFromString(signedSoap);
            return soapMessage;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private X509Certificate getCertificate() {
        KalkanProvider kalkanProvider = new KalkanProvider();
        Security.addProvider(kalkanProvider);
        KncaXS.loadXMLSecurity();
        InputStream inStream = null;
        try {
            inStream = getClass().getClassLoader().getResourceAsStream(SHEP_CERT_FILE);

            CertificateFactory cf = CertificateFactory.getInstance("X.509", kalkanProvider.getName());
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            return cert;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private SOAPMessage getSoapWithoutSign(String xml) {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = dbf.newDocumentBuilder();

            Document doc = documentBuilder.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));

            Element rootEl = (Element) doc.getFirstChild();
            NodeList list1 = rootEl.getElementsByTagName("wsse:Security");
            if (list1 != null) {
                if (list1.getLength() > 0) {
                    Node wsseNode = list1.item(0);
                    wsseNode.getParentNode().removeChild(wsseNode);
                }
            }
            String diffXml = nodeToString(rootEl);
            System.out.println("XML without sign");
            System.out.println(diffXml);
            SOAPMessage message = createSOAPFromString(diffXml);
            try {
                message.getSOAPBody().removeAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
                message.getSOAPBody().removeNamespaceDeclaration("wsu");
            } catch (SOAPException e) {
                e.printStackTrace();
            }
            return message;
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SOAPMessage getErrorSoap(String xml, String errorText) {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = dbf.newDocumentBuilder();

            Document doc = documentBuilder.parse(new ByteArrayInputStream(xml.getBytes("UTF-8")));

            Element rootEl = (Element) doc.getFirstChild();
            NodeList list1 = rootEl.getElementsByTagName("wsse:Security");
            if (list1 != null) {
                if (list1.getLength() > 0) {
                    Node wsseNode = list1.item(0);
                    wsseNode.getParentNode().removeChild(wsseNode);
                }
            }

            Node node =  rootEl.getElementsByTagName("sessionId").item(0);
            node.setTextContent(errorText);

            String diffXml = nodeToString(rootEl);
            SOAPMessage message = createSOAPFromString(diffXml);
            try {
                message.getSOAPBody().removeAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
                message.getSOAPBody().removeNamespaceDeclaration("wsu");
            } catch (SOAPException e) {
                e.printStackTrace();
            }
            return message;
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String nodeToString(Node node) {
        StringWriter sw = new StringWriter();
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            t.setOutputProperty(OutputKeys.INDENT, "yes");
            t.transform(new DOMSource(node), new StreamResult(sw));
        } catch (TransformerException te) {
            System.out.println("nodeToString Transformer Exception");
        }
        return sw.toString();
    }

    public static SOAPMessage createSOAPFromString(String xmlString) {
        SOAPMessage message = null;
        try {
            message = MessageFactory.newInstance().createMessage();
            SOAPPart soapPart = message.getSOAPPart();
            ByteArrayInputStream stream = null;
            try {
                stream = new ByteArrayInputStream(xmlString.getBytes("UTF-8"));
            } catch (UnsupportedEncodingException e1) {
                e1.printStackTrace();
            }
            StreamSource source = new StreamSource(stream);
            soapPart.setContent(source);
            try {
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (SOAPException e) {
            e.printStackTrace();
        }
        return message;
    }
}
