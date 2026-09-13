package org.keycloak.protocol.oid4vc.vp.request;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateSummaryTest {

    private static TestTrustChain chain;

    @BeforeAll
    static void generatePki() {
        chain = new TestTrustChain();
    }

    @Test
    void itReportsWhoTheCertificateNamesAndWhoSignedIt() {
        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, Instant.now());

        assertEquals(chain.issuerCert.getSubjectX500Principal().getName(), summary.subject());
        assertEquals(chain.issuerCert.getIssuerX500Principal().getName(), summary.issuer());
        assertEquals(chain.issuerCert.getSerialNumber().toString(16), summary.serialNumber());
    }

    /**
     * ISO-8601 strings rather than {@code Instant}, because this record is serialised to JSON and an
     * {@code Instant} comes out as a floating-point epoch whose shape depends on how the mapper
     * happens to be configured. Measured against a running 26.7.2: {@code 1788851296.0}. A summary
     * whose format a reader has to guess is not a summary.
     */
    @Test
    void itReportsTheValidityWindowAsIso8601() {
        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, Instant.now());

        assertEquals(chain.issuerCert.getNotBefore().toInstant().toString(), summary.notBefore());
        assertEquals(chain.issuerCert.getNotAfter().toInstant().toString(), summary.notAfter());
        assertTrue(summary.notBefore().endsWith("Z"),
            "an instant with no zone is one a reader cannot place: " + summary.notBefore());
    }

    /**
     * The one field nobody can check by eye. It is what the wallet is told, and what it compares the
     * x5c against; computed anywhere but here, the screen could disagree with the request.
     */
    @Test
    void itReportsTheClientIdTheWalletWillBeToldVerbatim() {
        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, Instant.now());

        assertEquals(VerifierClientId.x509Hash(chain.issuerCert), summary.clientId(),
            "the summary must show the identifier the request actually announces");
    }

    @Test
    void aCertificateInsideItsWindowIsValidNow() {
        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, Instant.now());

        assertTrue(summary.validNow(), "a freshly generated certificate is valid now");
        assertFalse(summary.expired(), "and it has not expired");
    }

    /**
     * Asked about a moment past the certificate's end, the summary must say so. A verifier whose
     * certificate has lapsed is refused by every wallet, with a trust error that names nothing —
     * this is the screen that can name it.
     */
    @Test
    void aCertificateAskedAboutAfterItsEndIsExpired() {
        Instant afterTheEnd = chain.issuerCert.getNotAfter().toInstant().plusSeconds(1);

        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, afterTheEnd);

        assertTrue(summary.expired(), "past notAfter, the certificate is expired");
        assertFalse(summary.validNow(), "and it is no longer usable");
    }

    @Test
    void aCertificateAskedAboutBeforeItsStartIsNotYetValid() {
        Instant beforeTheStart = chain.issuerCert.getNotBefore().toInstant().minusSeconds(1);

        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, beforeTheStart);

        assertTrue(summary.notYetValid(), "before notBefore, the certificate is not yet valid");
        assertFalse(summary.validNow(), "and it is not usable either");
    }

    @Test
    void itReportsTheKeyItCarries() {
        CertificateSummary summary = CertificateSummary.of(chain.issuerCert, Instant.now());

        assertEquals("EC", summary.keyType(), "the verifier signs with an EC key");
        assertEquals("P-256", summary.curve(), "on the only curve this path accepts");
    }
}
