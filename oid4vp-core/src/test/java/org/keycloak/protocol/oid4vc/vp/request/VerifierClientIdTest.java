package org.keycloak.protocol.oid4vc.vp.request;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link VerifierClientId} derives the {@code client_id} from the signing certificate under
 * OID4VP's {@code x509_hash} scheme.
 *
 * <p>The reference case is not a value recomputed here: it is the official EUDI verifier's real
 * certificate, checked against the {@code client_id} its own request carries. Standard base64
 * instead of base64url, kept padding, or a digest over the PEM rather than the DER would all show
 * up here.
 */
class VerifierClientIdTest {

    /** {@code x5c[0]} du Request Object servi par verifier-backend.eudiw.dev le 2026-08-12. */
    private static final String REFERENCE_VERIFIER_CERT_B64 =
          "MIIC9DCCApqgAwIBAgIUEXkPkkiIGIHYC9Mf5YREVvZoIxgwCgYIKoZIzj0EAwIwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAw"
        + "MjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJFVTAeFw0yNjA3MTYxMDI4"
        + "MzVaFw0yODA3MTUxMDI4MzRaMFExGDAWBgNVBAMMD1ZlcmlmaWVyIFNpZ25lcjELMAkGA1UEBhMCRVUxDjAMBgNVBAoMBU5pc2N5"
        + "MRgwFgYDVQRhDA9MRUlFVS05ODc2NTQzMjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATgrGCmIf7kbMynUCKUtoR/dzqIFy5C"
        + "GkFTavBue92IcuNfUSdNr380c3VwG83DfblOkZKZfERIn6ggJtdR+Ccco4IBSDCCAUQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAW"
        + "gBRCUFC+ELgQ8J1EXI2/qxAI7ifcSTBZBggrBgEFBQcBAQRNMEswSQYIKwYBBQUHMAKGPWh0dHBzOi8vcHJlcHJvZC5wa2kuZXVk"
        + "aXcuZGV2L2FpYS9QSURJc3N1ZXJDQTAyLUVVLmNhY2VydC5wZW0wLgYDVR0RBCcwJYYjaHR0cHM6Ly92ZXJpZmllci1iYWNrZW5k"
        + "LmV1ZGl3LmRldi8wFAYDVR0gBA0wCzAJBgcEAIvsRgECMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVk"
        + "aXcuZGV2L2NybC9waWRfQ0FfRVVfMDIuY3JsMB0GA1UdDgQWBBRJtuPmQxnFsGs4S6U5eR9uGdjq+TAOBgNVHQ8BAf8EBAMCB4Aw"
        + "CgYIKoZIzj0EAwIDSAAwRQIgIP2Y3XbO+/T/B9/lLaiw9UN8ZkMNqPwAdm0DoZF//QECIQD2gDmAO8q/q3tDptT3yWmtG1izZpCG"
        + "oIVAQ/fB3l7/tA==";

    /** The {@code client_id} that same Request Object carries. */
    private static final String REFERENCE_CLIENT_ID =
        "x509_hash:FTTP4DJV_P7icSZwBAo8cifSpYy8Sph0K1gZdbmaQh4";

    @Test
    void derives_the_client_id_the_reference_verifier_publishes_for_its_own_certificate() throws Exception {
        X509Certificate cert = decode(REFERENCE_VERIFIER_CERT_B64);

        assertEquals(REFERENCE_CLIENT_ID, VerifierClientId.x509Hash(cert));
    }

    private static X509Certificate decode(String base64Der) throws Exception {
        byte[] der = Base64.getDecoder().decode(base64Der);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(der));
    }
}
