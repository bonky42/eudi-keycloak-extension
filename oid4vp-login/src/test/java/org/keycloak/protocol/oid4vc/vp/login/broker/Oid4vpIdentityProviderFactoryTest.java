package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.provider.ProviderConfigProperty;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class Oid4vpIdentityProviderFactoryTest {

    private static final String SERVICES_RESOURCE =
        "META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory";

    private static final Set<String> EXPECTED_CONFIG_NAMES = Set.of(
        Oid4vpConfig.TRUST_ANCHORS_PEM,
        Oid4vpConfig.SIGNING_KEY_PEM,
        Oid4vpConfig.SIGNING_CERT_PEM,
        Oid4vpConfig.DCQL_QUERY_JSON,
        Oid4vpConfig.MATCHING_CLAIM,
        Oid4vpConfig.TTL_SECONDS,
        Oid4vpConfig.REQUEST_PURPOSE,
        Oid4vpConfig.SUBJECT_CLAIM,
        Oid4vpConfig.SUBJECT_POLICY,
        Oid4vpConfig.OWN_VCT,
        Oid4vpConfig.REISSUE_BEFORE_SECONDS,
        Oid4vpConfig.OWN_CREDENTIAL_CONFIG_ID,
        Oid4vpConfig.SUBJECT_CLAIM_BY_VCT,
        Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM);

    @Test
    void getIdIsOid4vp() {
        assertEquals("oid4vp", new Oid4vpIdentityProviderFactory().getId());
    }

    @Test
    void getNameIsNonEmpty() {
        assertNotNull(new Oid4vpIdentityProviderFactory().getName());
        assertFalse(new Oid4vpIdentityProviderFactory().getName().isBlank());
    }

    @Test
    void getConfigPropertiesContainsExactlyTheOid4vpConfigConstants() {
        List<ProviderConfigProperty> properties = new Oid4vpIdentityProviderFactory().getConfigProperties();

        Set<String> actualNames = properties.stream()
            .map(ProviderConfigProperty::getName)
            .collect(Collectors.toSet());

        assertEquals(EXPECTED_CONFIG_NAMES, actualNames,
            "config property names must exactly equal the Oid4vpConfig.* constants (no drift)");
        assertEquals(EXPECTED_CONFIG_NAMES.size(), properties.size(), "no duplicate config property names");
    }

    @Test
    void createConfigReturnsFreshIdentityProviderModel() {
        assertNotNull(new Oid4vpIdentityProviderFactory().createConfig());
    }

    @Test
    void createBuildsOid4vpIdentityProvider() {
        var provider = new Oid4vpIdentityProviderFactory().create(null, new org.keycloak.models.IdentityProviderModel());
        assertInstanceOf(Oid4vpIdentityProvider.class, provider);
    }

    @Test
    void servicesResourceIsOnClasspathAndNamesTheFactory() throws IOException {
        Enumeration<URL> resources = getClass().getClassLoader().getResources(SERVICES_RESOURCE);
        assertTrue(resources.hasMoreElements(), "services resource must be on the classpath: " + SERVICES_RESOURCE);

        boolean found = false;
        while (resources.hasMoreElements()) {
            URL url = resources.nextElement();
            try (InputStream in = url.openStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().equals(Oid4vpIdentityProviderFactory.class.getName())) {
                        found = true;
                    }
                }
            }
        }
        assertTrue(found, "services resource must reference " + Oid4vpIdentityProviderFactory.class.getName());
    }

    /**
     * Without this, every rule in {@link Oid4vpIdentityProviderConfig} is dead code in production.
     *
     * <p>Keycloak reaches {@code validate} through the model that {@code createConfig()} hands
     * back; returning a bare {@code IdentityProviderModel} would leave the unit tests of those
     * rules perfectly green while nothing ever called them. This assertion is the wiring, and it is
     * the one worth having.</p>
     */
    @Test
    void createConfigReturnsTheModelThatValidates() {
        assertInstanceOf(Oid4vpIdentityProviderConfig.class,
            new Oid4vpIdentityProviderFactory().createConfig(),
            "createConfig must return the validating model, or no rule is ever enforced");
    }

    /**
     * The declaration and the enforcement must name the same fields.
     *
     * <p>The console drops the flag when it renders a third-party provider — measured against
     * 26.7.2 — so nothing shows today. It is declared anyway: it travels in the payload the console
     * already fetches, so whatever renders it later reads this list rather than restating it.</p>
     */
    @Test
    void thePropertiesMarkedRequiredAreExactlyTheOnesValidateDemands() {
        Set<String> marked = new Oid4vpIdentityProviderFactory().getConfigProperties().stream()
            .filter(ProviderConfigProperty::isRequired)
            .map(ProviderConfigProperty::getName)
            .collect(Collectors.toSet());

        assertEquals(Oid4vpIdentityProviderConfig.REQUIRED_FIELDS.keySet(), marked,
            "a field demanded by validate but not marked, or the reverse, is a form that disagrees "
                + "with the server about what is mandatory");
    }

    /** A refusal naming a label the form does not use sends the reader hunting for nothing. */
    @Test
    void theRequiredFieldLabelsMatchThePropertyLabels() {
        var labels = new Oid4vpIdentityProviderFactory().getConfigProperties().stream()
            .collect(Collectors.toMap(ProviderConfigProperty::getName, ProviderConfigProperty::getLabel));

        Oid4vpIdentityProviderConfig.REQUIRED_FIELDS.forEach((key, label) ->
            assertEquals(labels.get(key), label,
                "the message for " + key + " names a label the form does not use"));
    }
}
