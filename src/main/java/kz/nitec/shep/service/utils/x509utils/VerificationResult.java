package kz.nitec.shep.service.utils.x509utils;

public enum VerificationResult
{
    SUCCESS(0),
    CORRUPTED_CERT(1),
    CORRUPTED_XML(2),
    FAILURE_EXPIRED(3),
    FAILURE_NOT_YET_VALID(4),
    FAILURE_CHAIN_INVALID(5),
    FAILURE_REVOCED(6),
    FAILURE_UNKNOWN(7),
    FAILURE_BAD_SIGNATURE(8),
    // Сертификат не предназначен для ЭЦП
    FAILURE_WRONG_KEYUSAGE(9),
    // Отсутствует метка времени
    FAILURE_TSP_IS_NULL(10),
    // Метка времени не действительна, т.к. хэш подписи и хэш в метке времени не совпадают
    FAILURE_TSP_WRONG(11),
    // Ошибка при проверке метки времени
    FAILURE_TSP_ERROR(15),
    // Отсутсвует OCSP-квитанция
    FAILURE_OCSP_IS_NULL(12),
    // Ошибка проверки OCSP
    FAILURE_OCSP_ERROR(13),
    // В OCSP-квитанции не найден проверяемый сертификат
    FAILURE_OCSP_USER_CERT_NOT_FOUND(14);

    private int code;

    VerificationResult(int code)
    {
        this.code = code;
    }

    public int getCode()
    {
        return code;
    }
}