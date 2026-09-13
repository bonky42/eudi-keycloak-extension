package org.keycloak.protocol.oid4vc.vp.login.admin;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.oid4vc.vp.login.keys.Oid4vpVerifierKeyProvider;
import org.keycloak.protocol.oid4vc.vp.login.keys.Oid4vpVerifierKeyProviderFactory;
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

    private static final String COMPONENT_ID = "a-key-component";

    private static Map<String, String> namingTheKey() {
        Map<String, String> config = new HashMap<>();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, COMPONENT_ID);
        return config;
    }

    /** The realm as it really holds the key: the real provider, from real material. */
    private static java.util.stream.Stream<KeyWrapper> realmHoldingTheKey() {
        try {
            MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
            config.putSingle(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM,
                toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()));
            config.putSingle(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM,
                toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
            ComponentModel model = new ComponentModel();
            model.setId(COMPONENT_ID);
            model.setProviderId(Oid4vpVerifierKeyProviderFactory.ID);
            model.setConfig(config);
            return new Oid4vpVerifierKeyProvider(model).getKeysStream();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static java.util.stream.Stream<KeyWrapper> emptyRealm() {
        return java.util.stream.Stream.empty();
    }

    @Test
    void itSummarisesTheCertificateOfTheKeyTheProviderNames() throws Exception {
        CertificateSummary summary = SigningCertificateResource
            .summarise(namingTheKey(), SigningCertificateResourceTest::realmHoldingTheKey)
            .orElseThrow();

        assertEquals(chain.issuerCert.getSubjectX500Principal().getName(), summary.subject());
        assertEquals(VerifierClientId.x509Hash(chain.issuerCert), summary.clientId());
        assertTrue(summary.validNow());
    }

    /**
     * A provider naming no key yet is a form being filled in, not a fault. Empty is the answer,
     * which the endpoint turns into a 404 — "nothing to show here" — and which lets a console render
     * an empty panel rather than an alert.
     *
     * <p>This state was unreachable until the PEM fields went away: phase 1 made them mandatory, so
     * a provider without signing material could not be saved at all.</p>
     */
    @Test
    void aProviderNamingNoKeyHasNothingToSummarise() {
        assertEquals(Optional.empty(),
            SigningCertificateResource.summarise(Map.of(), SigningCertificateResourceTest::emptyRealm));
    }

    @Test
    void aBlankReferenceCountsAsAbsent() {
        assertEquals(Optional.empty(), SigningCertificateResource.summarise(
            Map.of(Oid4vpConfig.SIGNING_KEY_REF, "   "), SigningCertificateResourceTest::emptyRealm));
    }

    @Test
    void aNullConfigurationCountsAsAbsent() {
        assertEquals(Optional.empty(),
            SigningCertificateResource.summarise(null, SigningCertificateResourceTest::emptyRealm));
    }

    /**
     * A dangling reference is not absence, and the difference is the whole value of this endpoint:
     * it must say so here rather than surface later as a wallet refusing the request for reasons
     * that name none of it.
     */
    @Test
    void aReferenceToAKeyThatIsGoneIsNotTreatedAsAbsent() {
        assertThrows(IllegalArgumentException.class, () -> SigningCertificateResource.summarise(
            namingTheKey(), SigningCertificateResourceTest::emptyRealm));
    }
}
