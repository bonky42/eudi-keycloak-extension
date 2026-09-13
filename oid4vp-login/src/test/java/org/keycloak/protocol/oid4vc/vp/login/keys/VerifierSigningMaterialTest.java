package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifierSigningMaterialTest {

    private static final String COMPONENT_ID = "a-key-component";

    private static TestTrustChain chain;

    @BeforeAll
    static void generatePki() {
        chain = new TestTrustChain();
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    /** The legacy shape: the pair pasted into the identity provider's own configuration. */
    private static Map<String, String> pemConfig() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put(Oid4vpConfig.SIGNING_KEY_PEM, toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()));
        config.put(Oid4vpConfig.SIGNING_CERT_PEM, toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
        return config;
    }

    /**
     * A real key, produced by the real provider from real material — the realm would publish exactly
     * this. Nothing here is a stand-in.
     */
    private static Stream<KeyWrapper> realmHolding(java.security.KeyPair pair,
                                                   java.security.cert.X509Certificate cert,
                                                   String componentId) throws Exception {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.putSingle(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM,
            toPem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        config.putSingle(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM,
            toPem("CERTIFICATE", cert.getEncoded()));
        ComponentModel model = new ComponentModel();
        model.setId(componentId);
        model.setProviderId(Oid4vpVerifierKeyProviderFactory.ID);
        model.setConfig(config);
        return new Oid4vpVerifierKeyProvider(model).getKeysStream();
    }

    private static Stream<KeyWrapper> emptyRealm() {
        return Stream.empty();
    }

    @Test
    void withoutAReferenceItReadsThePairPastedIntoTheProvider() throws Exception {
        VerifierSigningMaterial material = VerifierSigningMaterial.resolve(
            new Oid4vpConfig(pemConfig()), VerifierSigningMaterialTest::emptyRealm);

        assertEquals(chain.issuerCert, material.certificate());
        assertEquals(chain.issuerKeyPair.getPrivate(), material.keyPair().getPrivate());
    }

    @Test
    void aBlankReferenceCountsAsNoReference() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, "   ");

        VerifierSigningMaterial material = VerifierSigningMaterial.resolve(
            new Oid4vpConfig(config), VerifierSigningMaterialTest::emptyRealm);

        assertEquals(chain.issuerCert, material.certificate());
    }

    /**
     * The point of the whole exercise: named a key, it takes the key, and the PEM fields are not
     * consulted at all — here they name a different certificate entirely, and the referenced one
     * wins.
     */
    @Test
    void aReferenceNamesAKeyInTheRealmAndThatKeyWins() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, COMPONENT_ID);

        VerifierSigningMaterial material = VerifierSigningMaterial.resolve(
            new Oid4vpConfig(config),
            () -> {
                try {
                    return realmHolding(chain.cardIssuerKeyPair, chain.cardIssuerCert, COMPONENT_ID);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });

        assertEquals(chain.cardIssuerCert, material.certificate(),
            "the referenced key must win over the pasted pair");
        assertEquals(chain.cardIssuerKeyPair.getPrivate(), material.keyPair().getPrivate());
    }

    /**
     * A reference to a key that is gone is worth naming loudly. It happens for one ordinary reason:
     * someone deleted the key component and left the provider pointing at it — and the alternative,
     * falling back to whatever PEM is lying around, would sign requests with an identity nobody
     * chose.
     */
    @Test
    void aReferenceToAKeyThatIsNotThereIsRefused() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, "deleted-component");

        IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
            () -> VerifierSigningMaterial.resolve(new Oid4vpConfig(config),
                VerifierSigningMaterialTest::emptyRealm));

        assertTrue(refusal.getMessage().contains("deleted-component"),
            "the message must name the key that is missing: " + refusal.getMessage());
    }

    @Test
    void keysBelongingToAnotherComponentAreIgnored() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, "the-one-we-want");

        assertThrows(IllegalArgumentException.class,
            () -> VerifierSigningMaterial.resolve(new Oid4vpConfig(config),
                () -> {
                    try {
                        return realmHolding(chain.cardIssuerKeyPair, chain.cardIssuerCert, "someone-else");
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }));
    }

    /**
     * The certificate travels as the Request Object's x5c and the client_id is derived from it, so a
     * key without one cannot do this job. Better to say so than to sign a request that announces
     * nothing.
     */
    @Test
    void aReferencedKeyWithoutACertificateIsRefused() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, COMPONENT_ID);

        KeyWrapper certificateless = new KeyWrapper();
        certificateless.setProviderId(COMPONENT_ID);
        certificateless.setPrivateKey(chain.issuerKeyPair.getPrivate());

        IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
            () -> VerifierSigningMaterial.resolve(new Oid4vpConfig(config),
                () -> Stream.of(certificateless)));

        assertTrue(refusal.getMessage().contains("certificate"), refusal.getMessage());
    }

    @Test
    void thePublicHalfComesFromTheCertificateSoTheTwoCannotDisagree() throws Exception {
        Map<String, String> config = pemConfig();
        config.put(Oid4vpConfig.SIGNING_KEY_REF, COMPONENT_ID);

        VerifierSigningMaterial material = VerifierSigningMaterial.resolve(
            new Oid4vpConfig(config),
            () -> {
                try {
                    return realmHolding(chain.issuerKeyPair, chain.issuerCert, COMPONENT_ID);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });

        assertEquals(material.certificate().getPublicKey(), material.keyPair().getPublic());
    }
}
