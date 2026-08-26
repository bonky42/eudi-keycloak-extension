package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.security.cert.Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class Oid4vpConfigTest {

    private static final String PID_QUERY = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [
                { "path": ["given_name"] },
                { "path": ["age_over_18"] }
              ]
            }
          ]
        }""";

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    private static Map<String, String> buildConfig(TestTrustChain chain) throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put(Oid4vpConfig.TRUST_ANCHORS_PEM, toPem("CERTIFICATE", chain.caCert.getEncoded()));
        config.put(Oid4vpConfig.SIGNING_KEY_PEM, toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()));
        config.put(Oid4vpConfig.SIGNING_CERT_PEM, toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
        config.put(Oid4vpConfig.DCQL_QUERY_JSON, PID_QUERY);
        config.put(Oid4vpConfig.MATCHING_CLAIM, "email");
        return config;
    }

    @Test
    void readsTrustStoreSigningKeyDcqlAndDefaults() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);

        Oid4vpConfig cfg = new Oid4vpConfig(config);

        // trust store chains the test issuer cert to the CA anchor
        Certificate validated = cfg.trustStore().validateChain(List.of(chain.issuerCert));
        assertEquals(chain.caCert, validated);

        // signing key material
        assertNotNull(cfg.signingKey().getPrivate());
        assertEquals(chain.issuerCert, cfg.signingCert());

        // DCQL query
        assertEquals("pid", cfg.dcqlQuery().getCredentials().get(0).getId());

        // matching claim passthrough
        assertEquals("email", cfg.matchingClaim());

        // ttl default
        assertEquals(120, cfg.ttlSeconds());
    }

    @Test
    void matchingClaimIsNullWhenAbsent() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);
        config.remove(Oid4vpConfig.MATCHING_CLAIM);

        Oid4vpConfig cfg = new Oid4vpConfig(config);
        assertNull(cfg.matchingClaim());
    }

    @Test
    void ttlSecondsParsesConfiguredValue() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);
        config.put(Oid4vpConfig.TTL_SECONDS, "300");

        Oid4vpConfig cfg = new Oid4vpConfig(config);
        assertEquals(300, cfg.ttlSeconds());
    }

    @Test
    void subjectClaimDefaultsToSub() {
        Oid4vpConfig cfg = new Oid4vpConfig(new HashMap<>());
        assertEquals("sub", cfg.subjectClaim());
    }

    @Test
    void subjectClaimUsesConfiguredValue() {
        Map<String, String> m = new HashMap<>();
        m.put(Oid4vpConfig.SUBJECT_CLAIM, "personal_identifier");
        assertEquals("personal_identifier", new Oid4vpConfig(m).subjectClaim());
    }

    @Test
    void subjectClaimFallsBackToSubWhenBlank() {
        Map<String, String> m = new HashMap<>();
        m.put(Oid4vpConfig.SUBJECT_CLAIM, "   ");
        assertEquals("sub", new Oid4vpConfig(m).subjectClaim());
    }

    @Test
    void subjectPolicyDefaultsToReject() {
        assertEquals("REJECT", new Oid4vpConfig(new HashMap<>()).subjectPolicy());
    }

    @Test
    void ownVctIsNullWhenAbsentOrBlank() {
        assertNull(new Oid4vpConfig(new HashMap<>()).ownVct());
        assertNull(new Oid4vpConfig(Map.of(Oid4vpConfig.OWN_VCT, "  ")).ownVct());
    }

    @Test
    void reissueBeforeSecondsDefaultsToThirtyDays() {
        assertEquals(2_592_000, new Oid4vpConfig(new HashMap<>()).reissueBeforeSeconds());
        assertEquals(60, new Oid4vpConfig(Map.of(Oid4vpConfig.REISSUE_BEFORE_SECONDS, "60"))
            .reissueBeforeSeconds());
    }

    @Test
    void ownCredentialConfigIdIsNullWhenAbsentOrBlank() {
        assertNull(new Oid4vpConfig(new HashMap<>()).ownCredentialConfigId());
        assertNull(new Oid4vpConfig(Map.of(Oid4vpConfig.OWN_CREDENTIAL_CONFIG_ID, "  ")).ownCredentialConfigId());
        assertEquals("account-holder-card", new Oid4vpConfig(
            Map.of(Oid4vpConfig.OWN_CREDENTIAL_CONFIG_ID, " account-holder-card ")).ownCredentialConfigId());
    }

    @Test
    void subjectClaimByVctIsNullWhenUnset() {
        assertNull(new Oid4vpConfig(Map.of()).subjectClaimByVct(),
            "no table -> the global subjectClaim applies to every type, older realms untouched");
    }

    @Test
    void subjectClaimByVctIsTrimmed() {
        assertEquals("urn:eudi:pid:1=sub",
            new Oid4vpConfig(Map.of(Oid4vpConfig.SUBJECT_CLAIM_BY_VCT, "  urn:eudi:pid:1=sub  "))
                .subjectClaimByVct());
    }

    // ---- Pinned issuance anchors ---------------------------------------------

    @Test
    void ownIssuerAnchorsAreEmptyWhenUnset() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        assertTrue(new Oid4vpConfig(buildConfig(chain)).ownIssuerAnchors().isEmpty(),
            "unconfigured means empty, and empty refuses — the caller decides, not this accessor");
    }

    @Test
    void ownIssuerAnchorsParseABundle() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);
        // Les deux ancres sont dans trustAnchorsPem : c'est une rotation, pas une erreur de saisie.
        config.put(Oid4vpConfig.TRUST_ANCHORS_PEM,
            toPem("CERTIFICATE", chain.caCert.getEncoded())
                + toPem("CERTIFICATE", chain.rogueCaCert.getEncoded()));
        config.put(Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM,
            toPem("CERTIFICATE", chain.caCert.getEncoded())
                + toPem("CERTIFICATE", chain.rogueCaCert.getEncoded()));

        List<?> anchors = new Oid4vpConfig(config).ownIssuerAnchors();
        assertEquals(2, anchors.size(), "a bundle must yield every certificate it carries");
        assertTrue(anchors.contains(chain.caCert));
        assertTrue(anchors.contains(chain.rogueCaCert));
    }

    @Test
    void aPinnedAnchorAbsentFromTrustAnchorsIsReturnedAnyway() throws Exception {
        // Do NOT throw: an accessor that throws during a login turns an administrator's typo into
        // an error page. The anchor is returned as is, no chain will ever validate against it, and
        // the behaviour fails closed on its own. The ERROR logged here explains why.
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);
        config.put(Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM, toPem("CERTIFICATE", chain.rogueCaCert.getEncoded()));

        assertEquals(List.of(chain.rogueCaCert), new Oid4vpConfig(config).ownIssuerAnchors());
    }

    @Test
    void anUnparseablePinYieldsNoAnchorsRatherThanThrowing() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> config = buildConfig(chain);
        config.put(Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM, "this is not a PEM block");

        assertTrue(new Oid4vpConfig(config).ownIssuerAnchors().isEmpty(),
            "a malformed pin must fail closed, not blow up mid-login");
    }

    // ---- Request purpose ------------------------------------------------------

    @Test
    void requestPurposeDefaultsToAShippedMessageKey() {
        assertEquals("${oid4vpDefaultPurpose}", new Oid4vpConfig(Map.of()).requestPurpose(),
            "a stock install states a purpose rather than staying silent, which is what "
                + "OpenID4VP 1.0 section 6.2 asks for");
    }

    @Test
    void requestPurposeAcceptsAMessageKeyOrLiteralText() {
        assertEquals("${myOwnKey}",
            new Oid4vpConfig(Map.of(Oid4vpConfig.REQUEST_PURPOSE, "${myOwnKey}")).requestPurpose(),
            "a key is passed through untouched, for advancedMsg to resolve against the bundle");
        assertEquals("To prove you may enter the building",
            new Oid4vpConfig(Map.of(Oid4vpConfig.REQUEST_PURPOSE,
                "To prove you may enter the building")).requestPurpose(),
            "literal text is used as written, in whatever language the deployer wrote it");
    }

    @Test
    void anExplicitlyBlankPurposeMeansShowNothing() {
        assertNull(new Oid4vpConfig(Map.of(Oid4vpConfig.REQUEST_PURPOSE, "   ")).requestPurpose(),
            "clearing the field is a decision to say nothing, not a request for the default");
    }
}
