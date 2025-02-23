package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * User: akochkin
 * Date: 27.07.11
 * Time: 10:42
 */
public class CSPUtils
{
    public static DERObject getExtensionValue(X509Certificate X509Certificate, String oid) throws IOException
    {
        byte[] extensionValue = X509Certificate.getExtensionValue(oid);
        if (extensionValue != null)
        {
            ASN1InputStream is = new ASN1InputStream(extensionValue);
            DERObject derObject = is.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObject;
            byte[] octets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new
                    ByteArrayInputStream(octets));
            return oAsnInStream2.readObject();
        }
        return null;
    }
}
