package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class Oid4vpVerifierKeyProviderTest {

    private static TestTrustChain chain;

    @BeforeAll
    static void generatePki() {
        chain = new TestTrustChain();
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    private static ComponentModel componentWithVerifierKey() throws Exception {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM,
            toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()));
        config.putSingle(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM,
            toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
        ComponentModel model = new ComponentModel();
        model.setId("component-id");
        model.setProviderId(Oid4vpVerifierKeyProviderFactory.ID);
        model.setConfig(config);
        return model;
    }

    private static ComponentModel componentWith(java.security.KeyPair pair,
                                                java.security.cert.X509Certificate cert) throws Exception {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM,
            toPem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        config.putSingle(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM,
            toPem("CERTIFICATE", cert.getEncoded()));
        ComponentModel model = new ComponentModel();
        model.setId("component-id");
        model.setProviderId(Oid4vpVerifierKeyProviderFactory.ID);
        model.setConfig(config);
        return model;
    }

    private static KeyWrapper onlyKeyOf(ComponentModel model) {
        List<KeyWrapper> keys = new Oid4vpVerifierKeyProvider(model).getKeysStream().toList();
        assertEquals(1, keys.size(), "a verifier key component publishes exactly one key");
        return keys.get(0);
    }

    @Test
    void theImportedKeyIsPublishedWithItsCertificate() throws Exception {
        List<KeyWrapper> keys = new Oid4vpVerifierKeyProvider(componentWithVerifierKey())
            .getKeysStream().toList();

        assertEquals(1, keys.size(), "a verifier key component publishes exactly one key");
        KeyWrapper key = keys.get(0);
        assertEquals(chain.issuerKeyPair.getPrivate(), key.getPrivateKey(),
            "the private key must be the one that was imported");
        assertEquals(chain.issuerCert, key.getCertificate(),
            "the certificate must be the one that was imported");
        assertEquals(chain.issuerCert.getPublicKey(), key.getPublicKey(),
            "the public key comes from the certificate, so the two cannot drift apart");
    }

    /**
     * Keycloak draws a random kid when a keystore is loaded, which is why a credential scope cannot
     * pin a key that does not exist yet. Deriving it from the certificate makes it knowable before
     * the realm is created, so a fixture can name the key it means.
     */
    @Test
    void theSameCertificateAlwaysYieldsTheSameKid() throws Exception {
        String first = onlyKeyOf(componentWithVerifierKey()).getKid();
        String second = onlyKeyOf(componentWithVerifierKey()).getKid();

        assertNotNull(first, "a published key must carry a kid");
        assertEquals(first, second, "the kid must not change between two loads of the same material");
    }

    @Test
    void aDifferentCertificateYieldsADifferentKid() throws Exception {
        String verifier = onlyKeyOf(componentWithVerifierKey()).getKid();
        String other = onlyKeyOf(componentWith(chain.cardIssuerKeyPair, chain.cardIssuerCert)).getKid();

        assertNotEquals(verifier, other, "two different certificates must not share a kid");
    }

    /**
     * The Request Object is signed ES256 and nothing else: {@code SdJwtVpVerifier} hard-codes
     * P-256, and the registry issues P-256. Announcing anything else would describe a key that
     * cannot do the one job it exists for.
     */
    @Test
    void theKeyIsDeclaredAsAnEs256SigningKey() throws Exception {
        KeyWrapper key = onlyKeyOf(componentWithVerifierKey());

        assertEquals(KeyType.EC, key.getType(), "the imported material is an EC key");
        assertEquals(Algorithm.ES256, key.getAlgorithm(), "P-256 signing is ES256");
        assertEquals(KeyUse.SIG, key.getUse(), "this key signs the Request Object; it never encrypts");
    }

    /**
     * PASSIVE by default, and the reason is not caution. {@code AbstractCredentialSigner} falls back
     * to {@code getActiveKey(realm, SIG, algorithm)} whenever a credential scope does not pin its
     * {@code vc.signing_key_id} — so an ACTIVE ES256 verifier key could end up signing the cards
     * this realm issues. PASSIVE keeps it out of that draw while leaving it readable by kid.
     */
    @Test
    void aKeyIsPassiveUnlessItIsAskedToBeActive() throws Exception {
        assertEquals(KeyStatus.PASSIVE, onlyKeyOf(componentWithVerifierKey()).getStatus(),
            "a verifier key must not be a candidate for signing anything else by default");
    }

    /**
     * A key that does not name its component is not attached to anything: the realm key manager
     * groups by provider id, and the identity provider will select by it rather than by kid, which
     * changes whenever the material is replaced. Measured against a real server — the unit tests
     * were all green while nothing appeared under Realm settings, Keys.
     */
    @Test
    void theKeyNamesTheComponentThatProducedIt() throws Exception {
        ComponentModel model = componentWithVerifierKey();
        model.getConfig().putSingle(Attributes.PRIORITY_KEY, "42");

        KeyWrapper key = onlyKeyOf(model);

        assertEquals(model.getId(), key.getProviderId(),
            "the key must name the component it came from");
        assertEquals(42L, key.getProviderPriority(),
            "priority decides which provider wins when several offer the same algorithm");
    }

    @Test
    void aKeyAskedToBeActiveIsActive() throws Exception {
        ComponentModel model = componentWithVerifierKey();
        model.getConfig().putSingle(Attributes.ACTIVE_KEY, "true");

        assertEquals(KeyStatus.ACTIVE, onlyKeyOf(model).getStatus(),
            "the default must be a default, not a cage: an administrator can still activate it");
    }

    @Test
    void aDisabledKeyIsDisabledWhateverElseIsAskedFor() throws Exception {
        ComponentModel model = componentWithVerifierKey();
        model.getConfig().putSingle(Attributes.ENABLED_KEY, "false");
        model.getConfig().putSingle(Attributes.ACTIVE_KEY, "true");

        assertEquals(KeyStatus.DISABLED, onlyKeyOf(model).getStatus(),
            "disabled wins over active; otherwise turning a key off would not turn it off");
    }
}
