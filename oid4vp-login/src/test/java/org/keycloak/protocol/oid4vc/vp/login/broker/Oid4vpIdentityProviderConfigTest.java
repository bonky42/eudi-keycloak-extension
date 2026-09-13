package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the administration console refuses to save, and why it must be refused there.
 *
 * <p>Keycloak calls {@code IdentityProviderModel.validate} from
 * {@code RepresentationToModel.toModel}, which both {@code IdentityProvidersResource} (create) and
 * {@code IdentityProviderResource} (update) go through — verified against 26.7.2 bytecode. Throwing
 * here is therefore what turns a wrong configuration into a message on the screen of the person who
 * can still fix it, instead of a refused login later on.</p>
 *
 * <p>The rule below is not new knowledge: the same inconsistency is already reported in the server
 * log at authentication time. Moving it to save time is a change of audience, not of diagnosis.</p>
 */
class Oid4vpIdentityProviderConfigTest {

    /** The realm is unused by these rules; the signature demands one, so it is not fabricated. */
    private static Oid4vpIdentityProviderConfig config() {
        return new Oid4vpIdentityProviderConfig();
    }

    /**
     * A configuration carrying everything the provider dereferences without a guard. Anything the
     * accessors default (ttl, subject claim, subject policy) is deliberately absent: a default is a
     * decision, and demanding a value for it would make the form longer without making it safer.
     */
    private static Oid4vpIdentityProviderConfig complete() {
        Oid4vpIdentityProviderConfig cfg = config();
        cfg.getConfig().put(Oid4vpConfig.TRUST_ANCHORS_PEM, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----");
        cfg.getConfig().put(Oid4vpConfig.SIGNING_KEY_PEM, "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----");
        cfg.getConfig().put(Oid4vpConfig.SIGNING_CERT_PEM, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----");
        cfg.getConfig().put(Oid4vpConfig.DCQL_QUERY_JSON, "{\"credentials\":[]}");
        return cfg;
    }

    @Test
    void aConfigurationMissingTrustAnchorsIsRefused() {
        Oid4vpIdentityProviderConfig cfg = complete();
        cfg.getConfig().remove(Oid4vpConfig.TRUST_ANCHORS_PEM);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cfg.validate(null),
            "the trust store is built straight from this value: without it nothing can be verified");
        assertTrue(e.getMessage().contains("Trust Anchors (PEM)"),
            "the message must name the field as the form labels it: " + e.getMessage());
    }

    @Test
    void aConfigurationMissingTheDcqlQueryIsRefused() {
        Oid4vpIdentityProviderConfig cfg = complete();
        cfg.getConfig().remove(Oid4vpConfig.DCQL_QUERY_JSON);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cfg.validate(null),
            "with no query there is nothing to ask the wallet for");
        assertTrue(e.getMessage().contains("DCQL Query (JSON)"), e.getMessage());
    }

    @Test
    void aBlankValueCountsAsMissing() {
        Oid4vpIdentityProviderConfig cfg = complete();
        cfg.getConfig().put(Oid4vpConfig.SIGNING_KEY_PEM, "   ");

        assertThrows(IllegalArgumentException.class, () -> cfg.validate(null),
            "whitespace is what a cleared textarea leaves behind, and it parses no better than an "
                + "absent key");
    }

    /**
     * Fields the accessors default must NOT become mandatory. Keycloak marks what it needs to
     * function and leaves the rest alone; demanding a transaction TTL when 120 seconds is already
     * the answer would only teach administrators that the rules are arbitrary.
     */
    /**
     * The signing material is a choice between two shapes, so it is a rule rather than a required
     * field: name a realm key, or paste the pair. Naming a key is enough on its own — the PEM
     * fields being empty is the normal state once the key has moved.
     */
    @Test
    void namingARealmKeyIsEnoughOnItsOwn() {
        Oid4vpIdentityProviderConfig config = complete();
        config.getConfig().remove(Oid4vpConfig.SIGNING_KEY_PEM);
        config.getConfig().remove(Oid4vpConfig.SIGNING_CERT_PEM);
        config.getConfig().put(Oid4vpConfig.SIGNING_KEY_REF, "a-key-component");

        assertDoesNotThrow(() -> config.validate(null));
    }

    @Test
    void thePastedPairIsStillAccepted() {
        Oid4vpIdentityProviderConfig config = complete();

        assertDoesNotThrow(() -> config.validate(null));
    }

    @Test
    void aProviderWithNothingToSignWithIsRefused() {
        Oid4vpIdentityProviderConfig config = complete();
        config.getConfig().remove(Oid4vpConfig.SIGNING_KEY_PEM);
        config.getConfig().remove(Oid4vpConfig.SIGNING_CERT_PEM);

        IllegalArgumentException refusal =
            assertThrows(IllegalArgumentException.class, () -> config.validate(null));
        assertTrue(refusal.getMessage().contains("sign"), refusal.getMessage());
    }

    /** Half the legacy pair is not a shape: it would fail at the first login, not at save time. */
    @Test
    void aPastedKeyWithoutItsCertificateIsRefused() {
        Oid4vpIdentityProviderConfig config = complete();
        config.getConfig().remove(Oid4vpConfig.SIGNING_CERT_PEM);

        assertThrows(IllegalArgumentException.class, () -> config.validate(null));
    }

    @Test
    void fieldsThatHaveDefaultsAreNotDemanded() {
        assertDoesNotThrow(() -> complete().validate(null),
            "ttl, subject claim, subject policy and re-issue delay all default, so a configuration "
                + "without them is complete");
    }

    @Test
    void ownVctWithoutIssuerAnchorsIsRefused() {
        Oid4vpIdentityProviderConfig cfg = complete();
        cfg.getConfig().put(Oid4vpConfig.OWN_VCT, "urn:pn:card:1");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> cfg.validate(null),
            "an own vct with no issuer anchors refuses every card of that vct, and the refusal is "
                + "fatal to the whole transaction: it must not be saveable");

        assertTrue(e.getMessage().contains("Own Issuer Anchors"),
            "the message must name the field to fill, not the internal key: " + e.getMessage());
        assertTrue(e.getMessage().contains("Own Credential Type"),
            "and the field that made it mandatory: " + e.getMessage());
    }

    @Test
    void ownVctWithIssuerAnchorsIsAccepted() {
        Oid4vpIdentityProviderConfig cfg = complete();
        cfg.getConfig().put(Oid4vpConfig.OWN_VCT, "urn:pn:card:1");
        cfg.getConfig().put(Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----");

        assertDoesNotThrow(() -> cfg.validate(null),
            "the pair is complete, so nothing stands in the way of saving");
    }

    @Test
    void noOwnVctLeavesIssuerAnchorsIrrelevant() {
        Oid4vpIdentityProviderConfig cfg = complete();

        assertDoesNotThrow(() -> cfg.validate(null),
            "recognition-only is a legitimate configuration: with no own vct, issuing is off and "
                + "the anchors have nothing to pin");
    }
}
