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
import java.util.stream.Stream;
import java.util.HashMap;

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

    /** The realm as it really holds the key: the real provider, from real material. */
    private static Stream<KeyWrapper> realmHoldingTheKey() {
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

    private static Stream<KeyWrapper> emptyRealm() {
        return Stream.empty();
    }


    /**
     * Addressed by key rather than by provider, so a form can ask before anything is saved — and ask
     * again the moment the choice changes, rather than describing what the last save happened to
     * hold.
     */
    @Test
    void itSummarisesAKeyAskedForByItself() throws Exception {
        CertificateSummary summary = SigningCertificateResource
            .summariseKey(COMPONENT_ID, SigningCertificateResourceTest::realmHoldingTheKey);

        assertEquals(chain.issuerCert.getSubjectX500Principal().getName(), summary.subject());
        assertEquals(VerifierClientId.x509Hash(chain.issuerCert), summary.clientId());
    }

    @Test
    void aKeyAskedForByAnIdThatIsNotThereIsRefused() {
        IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
            () -> SigningCertificateResource.summariseKey(
                "deleted-component", SigningCertificateResourceTest::emptyRealm));

        assertTrue(refusal.getMessage().contains("deleted-component"), refusal.getMessage());
    }

}
