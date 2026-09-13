package org.keycloak.protocol.oid4vc.vp.login.admin;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.protocol.oid4vc.vp.request.CertificateSummary;
import org.keycloak.protocol.oid4vc.vp.request.VerifierClientId;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningCertificateResourceTest {

    private static TestTrustChain chain;

    @BeforeAll
    static void generatePki() {
        chain = new TestTrustChain();
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    private static Map<String, String> configWithCertificate() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put(Oid4vpConfig.SIGNING_CERT_PEM, toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
        return config;
    }

    @Test
    void itSummarisesTheCertificateTheProviderIsConfiguredWith() throws Exception {
        CertificateSummary summary = SigningCertificateResource.summarise(configWithCertificate())
            .orElseThrow();

        assertEquals(chain.issuerCert.getSubjectX500Principal().getName(), summary.subject());
        assertEquals(VerifierClientId.x509Hash(chain.issuerCert), summary.clientId());
        assertTrue(summary.validNow());
    }

    /**
     * A provider with no certificate yet is a form being filled in, not a fault. Empty is the
     * answer, which the endpoint turns into a 404 — "nothing to show here" — and which lets a
     * console render an empty panel rather than an alert.
     */
    @Test
    void aProviderWithoutACertificateHasNothingToSummarise() {
        assertEquals(Optional.empty(), SigningCertificateResource.summarise(Map.of()));
    }

    @Test
    void aBlankCertificateCountsAsAbsent() {
        assertEquals(Optional.empty(),
            SigningCertificateResource.summarise(Map.of(Oid4vpConfig.SIGNING_CERT_PEM, "   ")));
    }

    @Test
    void aNullConfigurationCountsAsAbsent() {
        assertEquals(Optional.empty(), SigningCertificateResource.summarise(null));
    }

    /**
     * Unreadable is not absent, and the difference is the whole value of this endpoint: a mistyped
     * certificate must say so here rather than surface later as a wallet refusing the request for
     * reasons that name none of it.
     */
    @Test
    void anUnreadableCertificateIsNotTreatedAsAbsent() {
        assertThrows(IllegalArgumentException.class, () -> SigningCertificateResource.summarise(
            Map.of(Oid4vpConfig.SIGNING_CERT_PEM, "this is not a PEM block")));
    }
}
