package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * SPI factory for the OID4VP identity-brokering provider. Declares the six admin-console
 * config fields whose keys ({@code trustAnchorsPem}, {@code signingKeyPem}, {@code signingCertPem},
 * {@code dcqlQueryJson}, {@code matchingClaim}, {@code ttlSeconds}) are read back by
 * {@link Oid4vpConfig} — reusing its constants here so the two can never drift apart.
 *
 * <p>Registered via {@code META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory}.</p>
 */
public class Oid4vpIdentityProviderFactory extends AbstractIdentityProviderFactory<Oid4vpIdentityProvider> {

    public static final String PROVIDER_ID = "oid4vp";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "OID4VP Wallet";
    }

    @Override
    public Oid4vpIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new Oid4vpIdentityProvider(session, model);
    }

    @Override
    public IdentityProviderModel createConfig() {
        // NOT a bare IdentityProviderModel. Keycloak reaches validate() through whatever this
        // returns, so a plain model would leave every rule in Oid4vpIdentityProviderConfig
        // unreachable while its unit tests stayed green.
        return new Oid4vpIdentityProviderConfig();
    }

    @Override
    public String getHelpText() {
        return "Authenticate users via an OID4VP (OpenID for Verifiable Presentations) wallet exchange.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>(List.of(
            new ProviderConfigProperty(
                Oid4vpConfig.TRUST_ANCHORS_PEM,
                "Trust Anchors (PEM)",
                "PEM-encoded certificate(s) trusted as roots for issuer/credential validation.",
                ProviderConfigProperty.TEXT_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.SIGNING_KEY_REF,
                "Signing Key (realm key)",
                "The id of a realm key component of type oid4vp-verifier-key. When set, the key and "
                    + "certificate come from Realm settings \u2192 Keys and the two PEM fields below are "
                    + "ignored \u2014 which is where they belong: a key held here is readable by anyone "
                    + "who can read this provider.",
                ProviderConfigProperty.STRING_TYPE,
                null),
            signingKeyProperty(),
            new ProviderConfigProperty(
                Oid4vpConfig.SIGNING_CERT_PEM,
                "Signing Certificate (PEM)",
                "PEM-encoded X.509 certificate matching the signing key, presented via x5c.",
                ProviderConfigProperty.TEXT_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.DCQL_QUERY_JSON,
                "DCQL Query (JSON)",
                "Digital Credentials Query Language document describing the requested presentation.",
                ProviderConfigProperty.TEXT_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.MATCHING_CLAIM,
                "Matching Claim",
                "Name of the verified claim used as the brokered user's identifier.",
                ProviderConfigProperty.STRING_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.TTL_SECONDS,
                "Transaction TTL (seconds)",
                "How long a presentation transaction stays valid before expiring. The login page "
                    + "counts it down, so a holder knows how long they have to reach their wallet.",
                ProviderConfigProperty.STRING_TYPE,
                "120"),
            new ProviderConfigProperty(
                Oid4vpConfig.REQUEST_PURPOSE,
                "Request Purpose",
                "Why this site is asking, shown to the holder on the login page before they open "
                    + "their wallet. OpenID4VP 1.0 section 6.2 asks for this and defines no way to "
                    + "send it to the wallet, so this page is the only place it can appear. Takes "
                    + "either literal text or a message key of the form ${myKey}, resolved against "
                    + "the login theme's bundle — the same convention as the consent screen. Clear "
                    + "the field to show nothing.",
                ProviderConfigProperty.STRING_TYPE,
                "${oid4vpDefaultPurpose}"),
            new ProviderConfigProperty(
                Oid4vpConfig.SUBJECT_CLAIM,
                "Subject Claim",
                "Name of the verified claim used as the subject identifier.",
                ProviderConfigProperty.STRING_TYPE,
                "sub"),
            new ProviderConfigProperty(
                Oid4vpConfig.SUBJECT_CLAIM_BY_VCT,
                "Subject Claim by Credential Type",
                "Comma-separated vct=claim pairs declaring which claim carries the subject for each "
                    + "credential type (e.g. urn:eudi:pid:1=sub,urn:pn:account-holder:1=sub). A type "
                    + "absent from this table falls back to Subject Claim. This table never decides "
                    + "the identity regime: verbatim use of the subject stays derived from Own "
                    + "Credential Type (vct).",
                ProviderConfigProperty.STRING_TYPE,
                null),
            subjectPolicyProperty(),
            new ProviderConfigProperty(
                Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM,
                "Own Issuer Anchors (PEM)",
                "PEM bundle of the anchor(s) entitled to sign Own Credential Type. A credential of "
                    + "that type validating under any other anchor is refused. REQUIRED as soon as "
                    + "Own Credential Type is set: left empty, every credential of that type is "
                    + "refused. Several certificates are accepted so that rotating the issuing "
                    + "authority can overlap. Each must also appear in Trust Anchors. TRANSITIONAL: "
                    + "replaced by an attribute on realm anchor sources once those exist.",
                ProviderConfigProperty.TEXT_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.OWN_VCT,
                "Own Credential Type (vct)",
                "vct of the credential this Keycloak issues itself. When set, a presentation of that "
                    + "type has its subject claim used verbatim as the federated identifier. Leave "
                    + "empty to disable issuance-related behaviour entirely.",
                ProviderConfigProperty.STRING_TYPE,
                null),
            new ProviderConfigProperty(
                Oid4vpConfig.REISSUE_BEFORE_SECONDS,
                "Re-issue Before (seconds)",
                "Offer a fresh card when the presented one expires within this many seconds.",
                ProviderConfigProperty.STRING_TYPE,
                "2592000"),
            new ProviderConfigProperty(
                Oid4vpConfig.OWN_CREDENTIAL_CONFIG_ID,
                "Own Credential Configuration Id",
                "credential_configuration_id of the credential scope this Keycloak issues itself. "
                    + "Used to resolve the holder's entitlement (UserVerifiableCredentialModel) so a "
                    + "revoked holder can no longer authenticate with an already-issued card.",
                ProviderConfigProperty.STRING_TYPE,
                null)));

        // Marked from the one list that also decides what validate() demands, so the form and the
        // server can never disagree about what is mandatory. Keycloak 26.7.2 does not render this
        // for a third-party provider — measured — but it does put it in the payload the console
        // fetches, which is where anything drawing the asterisks later will read it.
        properties.stream()
            .filter(property -> Oid4vpIdentityProviderConfig.REQUIRED_FIELDS.containsKey(property.getName()))
            .forEach(property -> property.setRequired(true));

        return properties;
    }

    /**
     * The only field here that must not be read back by anyone who can open the console.
     *
     * <p>{@code setSecret} is what Keycloak offers to say so, and what it buys has to be stated
     * plainly: for a COMPONENT the server replaces a secret value with asterisks on its way out,
     * but a broker goes through {@code StripSecretsUtils.stripBroker}, which takes no session and
     * therefore cannot look a provider's declared properties up — it masks {@code clientSecret} and
     * {@code authTokenClientSecret} by name and nothing else. So this flag does NOT keep the key on
     * the server; it travels to the console as part of the descriptor, and the OID4VP settings page
     * uses it to keep the key off the screen until it is asked for.</p>
     */
    private static ProviderConfigProperty signingKeyProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty(
            Oid4vpConfig.SIGNING_KEY_PEM,
            "Signing Key (PEM)",
            "PEM-encoded PKCS#8 EC private key used to sign the authorization request.",
            ProviderConfigProperty.TEXT_TYPE,
            null);
        property.setSecret(true);
        return property;
    }

    private static ProviderConfigProperty subjectPolicyProperty() {
        ProviderConfigProperty property = new ProviderConfigProperty(
            Oid4vpConfig.SUBJECT_POLICY,
            "Subject Policy",
            "What to do when the presentation carries no stable subject claim (the configured "
                + "Subject Claim is absent or blank). REJECT, the only supported value, refuses "
                + "the login rather than falling back to a guessed or hashed identifier.",
            ProviderConfigProperty.LIST_TYPE,
            Oid4vpConfig.SUBJECT_POLICY_REJECT);
        property.setOptions(List.of(Oid4vpConfig.SUBJECT_POLICY_REJECT));
        return property;
    }
}
