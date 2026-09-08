package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.Attributes;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.provider.ProviderConfigProperty;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Oid4vpVerifierKeyProviderFactoryTest {

    private static final String SERVICES_RESOURCE = "META-INF/services/org.keycloak.keys.KeyProviderFactory";

    private static TestTrustChain chain;

    @BeforeAll
    static void generatePki() {
        chain = new TestTrustChain();
    }

    private static String toPem(String type, byte[] der) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }

    private static ComponentModel model(String keyPem, String certPem) {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        if (keyPem != null) {
            config.putSingle(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM, keyPem);
        }
        if (certPem != null) {
            config.putSingle(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM, certPem);
        }
        ComponentModel component = new ComponentModel();
        component.setProviderId(Oid4vpVerifierKeyProviderFactory.ID);
        component.setConfig(config);
        return component;
    }

    private static ComponentModel wellFormed() throws Exception {
        return model(toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()),
            toPem("CERTIFICATE", chain.issuerCert.getEncoded()));
    }

    private static void validate(ComponentModel component) {
        new Oid4vpVerifierKeyProviderFactory().validateConfiguration(null, null, component);
    }

    @Test
    void theIdIsTheOneTheIdentityProviderWillReference() {
        assertEquals("oid4vp-verifier-key", new Oid4vpVerifierKeyProviderFactory().getId());
    }

    /**
     * The whole point of moving the key here. A component goes through
     * {@code StripSecretsUtils.stripComponent}, which takes a session and therefore CAN consult
     * this flag — unlike {@code stripBroker}, which masks by name and leaves everything else in
     * the clear, in the admin API and in admin events alike.
     */
    @Test
    void thePrivateKeyIsDeclaredSecret() {
        Optional<ProviderConfigProperty> privateKey =
            new Oid4vpVerifierKeyProviderFactory().getConfigProperties().stream()
                .filter(p -> Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM.equals(p.getName()))
                .findFirst();

        assertTrue(privateKey.isPresent(), "the private key must be a declared property");
        assertTrue(privateKey.get().isSecret(),
            "declared secret is what lets the server mask it on the way out");
    }

    @Test
    void theStatusSwitchesKeycloakExpectsAreOffered() {
        List<String> names = new Oid4vpVerifierKeyProviderFactory().getConfigProperties().stream()
            .map(ProviderConfigProperty::getName).toList();

        assertTrue(names.contains(Attributes.PRIORITY_KEY), "priority orders providers");
        assertTrue(names.contains(Attributes.ENABLED_KEY), "enabled is how a key is retired");
        assertTrue(names.contains(Attributes.ACTIVE_KEY), "active is what PASSIVE opts out of");
    }

    @Test
    void aWellFormedPairIsAccepted() throws Exception {
        assertDoesNotThrow(() -> validate(wellFormed()));
    }

    @Test
    void aMissingPrivateKeyIsRefused() throws Exception {
        ComponentValidationException refusal = assertThrows(ComponentValidationException.class,
            () -> validate(model(null, toPem("CERTIFICATE", chain.issuerCert.getEncoded()))));
        assertTrue(refusal.getMessage().contains("private key"), refusal.getMessage());
    }

    @Test
    void aMissingCertificateIsRefused() throws Exception {
        ComponentValidationException refusal = assertThrows(ComponentValidationException.class,
            () -> validate(model(toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()), null)));
        assertTrue(refusal.getMessage().contains("certificate"), refusal.getMessage());
    }

    /**
     * The refusal that matters. A key and a certificate that do not belong together produce a
     * Request Object signed by one identity and announcing another, and the wallet answers with a
     * trust failure that names neither — which is a long way from the mistake.
     */
    @Test
    void aKeyThatDoesNotMatchItsCertificateIsRefused() throws Exception {
        ComponentValidationException refusal = assertThrows(ComponentValidationException.class,
            () -> validate(model(toPem("PRIVATE KEY", chain.issuerKeyPair.getPrivate().getEncoded()),
                toPem("CERTIFICATE", chain.cardIssuerCert.getEncoded()))));
        assertTrue(refusal.getMessage().contains("does not match"), refusal.getMessage());
    }

    @Test
    void aCurveOtherThanP256IsRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair p384 = generator.generateKeyPair();

        ComponentValidationException refusal = assertThrows(ComponentValidationException.class,
            () -> validate(model(toPem("PRIVATE KEY", p384.getPrivate().getEncoded()),
                toPem("CERTIFICATE", chain.issuerCert.getEncoded()))));
        assertTrue(refusal.getMessage().contains("P-256"), refusal.getMessage());
    }

    @Test
    void theFactoryIsRegisteredUnderTheKeyProviderSpi() throws Exception {
        Enumeration<URL> resources =
            Thread.currentThread().getContextClassLoader().getResources(SERVICES_RESOURCE);
        boolean found = false;
        while (resources.hasMoreElements()) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                resources.nextElement().openStream(), StandardCharsets.UTF_8))) {
                found |= reader.lines()
                    .anyMatch(line -> line.trim().equals(Oid4vpVerifierKeyProviderFactory.class.getName()));
            }
        }
        assertTrue(found, "without this line Keycloak never loads the provider and the Keys screen "
            + "simply does not offer it — silently: " + SERVICES_RESOURCE);
    }
}
