package kz.nitec.shep.service.utils.x509utils;

import java.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: smirnov_v
 * Date: 20.10.2010
 */
public class VerificationData
{

    private VerificationResult verificationResult;
    private String subjectDN;
    private X509Certificate cert;

    public VerificationData()
    {
    }

    public VerificationData(VerificationResult verificationResult, String subjectDN
            , X509Certificate cert)
    {
        this.verificationResult = verificationResult;
        this.subjectDN = subjectDN;
        this.cert = cert;
    }

    public VerificationResult getVerificationResult()
    {
        return verificationResult;
    }

    public void setVerificationResult(VerificationResult verificationResult)
    {
        this.verificationResult = verificationResult;
    }

    public String getSubjectDN()
    {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN)
    {
        this.subjectDN = subjectDN;
    }

    public X509Certificate getCert()
    {
        return cert;
    }

    public void setCert(X509Certificate cert)
    {
        this.cert = cert;
    }

    public String toString()
    {
        return "VerificationResult [" + verificationResult + "]; subjectDN [" + subjectDN + "]";
    }
}
