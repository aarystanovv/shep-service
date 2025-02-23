package kz.nitec.shep.service.utils.x509utils;

import kz.gov.pki.kalkan.asn1.DERIA5String;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.x509.*;
import kz.gov.pki.kalkan.jce.provider.X509CRLObject;

import java.io.InputStream;
import java.net.URL;
import java.security.cert.*;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class CrlUtils
{

    private static final Map<String, X509CRL> crlMap = Collections.synchronizedMap(new HashMap<String, X509CRL>());
    private CertificateFactory certificateFactory;

    static
    {
        CryptoInitializer.initCrypto();
    }

    public CrlUtils(CertificateFactory certificateFactory)
    {
        this.certificateFactory = certificateFactory;
    }

    public void verifyCertInCRL(X509Certificate certificate) throws CRLException
    {
        loadCRL(certificate);
        synchronized (crlMap)
        {
            for (CRL crl : crlMap.values())
            {
                if (crl.isRevoked(certificate))
                {
                    String name = certificate.getSubjectDN().toString();
                    throw new CRLException("Certificate [" + name + "] revoked according to CRL");
                }
            }
        }
    }

    private void loadCRL(X509Certificate certificate) throws CRLException
    {
        try
        {
            DERObject derObj2 = CSPUtils.getExtensionValue(certificate, X509Extensions.CRLDistributionPoints.getId());
            if(derObj2==null) return;
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);
            for (DistributionPoint dp : distPoint.getDistributionPoints())
            {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME)
                {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName genName : genNames)
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier)
                        {
                            String url = DERIA5String.getInstance(genName.getName()).getString();
                            synchronized (crlMap)
                            {
                                X509CRL crlImpl = crlMap.get(url);

                                if (crlImpl != null && crlImpl.getNextUpdate().before(new Date()))
                                {
                                    crlMap.remove(url);
                                    crlImpl = null;
                                }

                                if (crlImpl == null)
                                {
                                    InputStream crlInputStream = new URL(url).openConnection().getInputStream();
                                    try
                                    {
                                        crlImpl = (X509CRLObject) certificateFactory.generateCRL(crlInputStream);
                                    } finally
                                    {
                                        crlInputStream.close();
                                    }

                                    crlMap.put(url, crlImpl);
                                }
                            }
                        }
                }
            }
        } catch (Exception ex)
        {
            throw new CRLException(ex);
        }
    }
}