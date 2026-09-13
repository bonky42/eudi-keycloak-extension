package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.vp.login.card.CardGrant;
import org.keycloak.protocol.oid4vc.vp.login.protocol.ClaimsToContext;
import org.keycloak.protocol.oid4vc.vp.login.keys.VerifierSigningMaterial;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VerifiedClaimsNotes;
import org.keycloak.protocol.oid4vc.vp.request.VerifierClientId;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the two offer-trigger decisions {@code authenticationFinished} makes —
 * the transient-IdP guard, and (as a corollary that also pins down the
 * {@code kc_action_parameter} format established from the 26.7.0 bytecode) that a
 * non-transient IdP with a fresh-card need arms the AIA client notes with a value that
 * {@code VerifiableCredentialOfferActionConfig.decodeConfig} — the real Keycloak class the
 * native {@code verifiable_credential_offer} action calls — can decode back correctly.
 *
 * <p>Two further decisions are covered: writing {@code oid4vp.fedid} onto the authenticated
 * {@code UserModel} at EVERY login rather than only at the first broker login, and the re-offer
 * decision reading the {@code CTX_CARDS} list of presented cards rather than a single
 * {@code vct}/{@code expiresAt} pair.</p>
 *
 * <p>Everything else {@code authenticationFinished} does (the {@link VerifiedClaimsNotes#ALL}
 * copy) is unchanged by these tasks and is intentionally left untested here: exercising the rest
 * meaningfully needs a running Keycloak.</p>
 */
class Oid4vpIdentityProviderTest {

    static {
        // IdentityProviderModel.isTransientUsers() first checks the TRANSIENT_USERS feature
        // (EXPERIMENTAL, disabled by Profile.defaults()) before it even looks at the
        // doNotStoreUsers config value; outside a running Keycloak, Profile.getInstance() is also
        // simply null until something initializes it. Enable it explicitly so config.isTransientUsers()
        // reflects config.setTransientUsers(...) the way it would in a real realm with the feature on.
        org.keycloak.common.Profile.init(org.keycloak.common.Profile.ProfileName.DEFAULT,
            Map.of(org.keycloak.common.Profile.Feature.TRANSIENT_USERS, true));
    }

    private static final String OWN_VCT = "urn:pn:account-holder:1";
    private static final String OTHER_VCT = "urn:eudi:pid:1";
    private static final String CREDENTIAL_CONFIG_ID = "account-holder-card";
    /** The client the holder is signing in to: the one the offer must name. */
    private static final String LOGIN_CLIENT_ID = "test-app";

    @Test
    void transientIdpArmsNoOfferEvenWhenReofferRuleWouldSayYes() throws Exception {
        IdentityProviderModel config = enabledConfig(true);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        // bootstrap case: would offer
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[{\"vct\":\"" + OTHER_VCT + "\"}]");

        new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx);

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "a transient IdP creates no account: nothing to attest, so no AIA is ever armed");
        assertNull(authSession.clientNotes.get(Constants.KC_ACTION_PARAMETER));
    }

    @Test
    void nonTransientIdpArmsOfferWithADecodableParameter() throws Exception {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setAuthenticatedUser(new FakeUser());
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        // login by PID: bootstrap
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[{\"vct\":\"" + OTHER_VCT + "\"}]");

        providerGranting(config, true).authenticationFinished(authSession, ctx);

        assertEquals("verifiable_credential_offer", authSession.clientNotes.get(Constants.KC_ACTION));
        String encodedParameter = authSession.clientNotes.get(Constants.KC_ACTION_PARAMETER);
        VerifiableCredentialOfferActionConfig decoded =
            VerifiableCredentialOfferActionConfig.decodeConfig(encodedParameter);
        assertEquals(CREDENTIAL_CONFIG_ID, decoded.getCredentialConfigurationId());
        // An unset `preAuthorized` means false to Keycloak, and the offer then becomes an
        // AuthorizationCodeGrant a wallet can only honour by replaying a full authorization code
        // flow in a browser. The holder has just authenticated, so the offer MUST be
        // pre-authorized or the bootstrap journey never closes.
        assertEquals(Boolean.TRUE, decoded.getPreAuthorized(),
            "an offer armed after a login must be pre-authorized");
        // Without clientId the pre-authorized code references no client and the token exchange
        // fails with "No client model for: null" — the QR code leads nowhere.
        assertEquals(LOGIN_CLIENT_ID, decoded.getClientId(),
            "the offer must name the client the holder is signing in to");
    }

    /** Task 8bis: create-credential-offer needs the entitlement granted first — see
     *  {@code Oid4vpIdentityProvider#createCardGrant}. A failed grant must skip the offer, not
     *  crash the login: the porter already proved their identity via the presentation. */
    @Test
    void nonTransientIdpSkipsOfferWhenTheGrantFails() throws Exception {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setAuthenticatedUser(new FakeUser());
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT); // would otherwise bootstrap

        assertDoesNotThrow(() -> providerGranting(config, false).authenticationFinished(authSession, ctx));

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "a failed grant must never leave the holder with an offer that create-credential-offer "
                + "would refuse (400 invalid_credential_offer_request)");
    }

    /** Task 8bis: {@code authenticationFinished} needs a {@code UserModel} to grant the
     *  entitlement to. Verified by disassembly that this is populated by the time Keycloak calls
     *  this method (see {@code Oid4vpIdentityProvider#createCardGrant} javadoc) — this test pins
     *  down the defensive fallback in case that assumption is ever broken by a Keycloak upgrade. */
    @Test
    void nonTransientIdpSkipsOfferWhenNoAuthenticatedUserIsOnTheSession() throws Exception {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession(); // no authenticated user set
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT); // would otherwise bootstrap

        assertDoesNotThrow(() -> providerGranting(config, true).authenticationFinished(authSession, ctx));

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION));
    }

    /**
     * A session with no client must abandon the offer, and abandon it BEFORE writing anything: the
     * guard sits ahead of the grant, so no entitlement is created on a path that arms nothing. This
     * test pins that by wiring a {@link CardGrant} which fails loudly if it is ever called.
     */
    @Test
    void nonTransientIdpSkipsGrantAndOfferWhenTheSessionHasNoClient() throws Exception {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setAuthenticatedUser(new FakeUser());
        authSession.client = null;
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT); // would otherwise bootstrap

        Oid4vpIdentityProvider provider = new Oid4vpIdentityProvider(null, config) {
            @Override protected CardGrant createCardGrant(String credentialConfigId) {
                return user -> {
                    throw new AssertionError("no entitlement may be granted on a path that arms "
                        + "no offer");
                };
            }
        };
        assertDoesNotThrow(() -> provider.authenticationFinished(authSession, ctx));

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION));
        assertNull(authSession.clientNotes.get(Constants.KC_ACTION_PARAMETER));
    }

    /**
     * Regression test: before the fix,
     * {@code authenticationFinished} read the scalar {@code CTX_EXPIRES_AT} context entry, which
     * the {@code complete()} rewrite had stopped writing it, {@code CTX_CARDS} superseding it —
     * {@code expiresAt} was therefore always {@code null}, {@link org.keycloak.protocol.oid4vc.vp.login.card.ReofferRule}'s
     * only false-return branch became unreachable, and a holder presenting a perfectly fresh own
     * card got re-offered a duplicate on EVERY login. This test hand-feeds {@code CTX_CARDS} (a
     * JSON array, one entry per presented card) the way a real login now produces it.
     */
    @Test
    void nonTransientIdpWithFreshOwnCardArmsNothing() throws Exception {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        long farFuture = java.time.Instant.now().getEpochSecond() + 10_000_000L;
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS,
            "[{\"vct\":\"" + OWN_VCT + "\",\"expiresAt\":" + farFuture + "}]");

        new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx);

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "a fresh presentation of our own card, well before its reissue window, offers nothing");
        assertNull(authSession.clientNotes.get(Constants.KC_ACTION_PARAMETER));
    }

    /**
     * Regression test. {@code Oid4vpConfig.reissueBeforeSeconds()} does
     * a bare {@code Integer.parseInt} on a {@code STRING_TYPE} admin console field — an admin typing
     * "30d" instead of "2592000" used to throw a {@code NumberFormatException} that escaped
     * {@code authenticationFinished} entirely (it was evaluated as a call argument, before the
     * method's own try/catch existed), turning an already-proven login into an error page. This test
     * proves the fail-open guarantee, it doesn't just describe it: even with {@code ownVct} left
     * unset — issuance nominally fully inert — a broken {@code reissueBeforeSeconds} must not
     * throw out of {@code authenticationFinished}, and must arm no AIA note.
     */
    @Test
    void brokenReissueBeforeSecondsNeverCrashesLoginEvenWhenOwnVctUnset() {
        IdentityProviderModel config = new IdentityProviderModel();
        config.setEnabled(true);
        Map<String, String> raw = new HashMap<>();
        raw.put(Oid4vpConfig.REISSUE_BEFORE_SECONDS, "oops"); // free text an admin could type
        config.setConfig(raw);
        config.setTransientUsers(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT);

        assertDoesNotThrow(() -> new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx));

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "ownVct is unset: phase 3b must stay inert even with garbage in an unrelated field");
    }

    /** Same defect, but on the exact scenario the reviewer traced: a real bootstrap login (own vct
     *  configured, presented vct differs) that WOULD normally arm the offer, except the admin also
     *  typed garbage into "Re-issue Before (seconds)". Must degrade to "no offer", not a crash. */
    @Test
    void brokenReissueBeforeSecondsNeverCrashesLoginOnABootstrapLogin() {
        IdentityProviderModel config = enabledConfig(false);
        Map<String, String> raw = new HashMap<>(config.getConfig());
        raw.put(Oid4vpConfig.REISSUE_BEFORE_SECONDS, "30d");
        config.setConfig(raw);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT); // would otherwise bootstrap

        assertDoesNotThrow(() -> new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx));

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "an unparsable reissueBeforeSeconds must be swallowed, not crash the login");
    }

    /** Fix round 1 / Important 4 regression test: a client-initiated AIA (?kc_action=... on /auth,
     *  landed in this exact client note by AuthorizationEndpoint before authentication even starts)
     *  must survive — our own offer must never clobber it. */
    @Test
    void existingClientInitiatedActionIsNotOverwritten() {
        IdentityProviderModel config = enabledConfig(false);

        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setClientNote(Constants.KC_ACTION, "UPDATE_PASSWORD");
        authSession.setClientNote(Constants.KC_ACTION_PARAMETER, "some-app-parameter");
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.VCT, OTHER_VCT); // would otherwise bootstrap

        new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx);

        assertEquals("UPDATE_PASSWORD", authSession.clientNotes.get(Constants.KC_ACTION),
            "the client's own AIA request must not be silently discarded");
        assertEquals("some-app-parameter", authSession.clientNotes.get(Constants.KC_ACTION_PARAMETER));
    }

    /**
     * Keycloak applies {@code ctx.setUserAttribute} only at the FIRST broker login, so an account
     * created before issuance existed never received it. {@code authenticationFinished} must write
     * {@code oid4vp.fedid} straight onto the {@code UserModel} at EVERY login, so that account
     * carries it from its next login on.
     */
    @Test
    void theFederatedIdIsWrittenOnEveryLogin() throws Exception {
        IdentityProviderModel config = enabledConfig(false);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        FakeUser user = new FakeUser();                       // compte d'avant la 3b : aucun attribut
        authSession.setAuthenticatedUser(user);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_FEDID, "https://pid.example:PID-1");
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[{\"vct\":\"urn:eudi:pid:1\"}]");

        providerGranting(config, true).authenticationFinished(authSession, ctx);

        assertEquals("https://pid.example:PID-1",
            user.getFirstAttribute(ClaimsToContext.FEDID_ATTRIBUTE),
            "without it, an older account receives cards with no subject and has them refused at "
                + "every login, with no signal saying why");
    }

    /** The transient guard stays at the HEAD of the method: no account, nothing to attest, and the
     *  {@code oid4vp.fedid} write must not even be attempted. */
    @Test
    void aTransientIdpWritesNoAttributeAtAll() throws Exception {
        IdentityProviderModel config = enabledConfig(true);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        FakeUser user = new FakeUser();
        authSession.setAuthenticatedUser(user);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_FEDID, "https://pid.example:PID-1");

        new Oid4vpIdentityProvider(null, config).authenticationFinished(authSession, ctx);

        assertNull(user.getFirstAttribute(ClaimsToContext.FEDID_ATTRIBUTE),
            "no durable account: nothing to attest");
    }

    /** "Do not write when the value is already right" is an explicit guard, not an accidental
     *  side effect. Without this test, removing it would fail nothing. */
    @Test
    void theFederatedIdIsNotRewrittenWhenAlreadyCorrect() throws Exception {
        IdentityProviderModel config = enabledConfig(false);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        FakeUser user = new FakeUser();
        user.attributes.put(ClaimsToContext.FEDID_ATTRIBUTE, "https://pid.example:PID-1");
        authSession.setAuthenticatedUser(user);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_FEDID, "https://pid.example:PID-1");
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[{\"vct\":\"urn:eudi:pid:1\"}]");

        providerGranting(config, true).authenticationFinished(authSession, ctx);

        assertEquals(0, user.setSingleAttributeCalls,
            "the value is already correct: an ordinary login must cause no write");
    }

    /** A realm whose user profile refuses unmanaged attributes must log and carry on, never turn
     *  an already proven login into an error page. Without this test, replacing the catch with a
     *  rethrow would fail nothing. */
    @Test
    void aFailingAttributeWriteNeverCostsTheLogin() throws Exception {
        IdentityProviderModel config = enabledConfig(false);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        FakeUser user = new FakeUser();
        user.setSingleAttributeThrows = new RuntimeException("realm refuses unmanaged attributes");
        authSession.setAuthenticatedUser(user);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_FEDID, "https://pid.example:PID-1");
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[{\"vct\":\"urn:eudi:pid:1\"}]");

        assertDoesNotThrow(() ->
            providerGranting(config, true).authenticationFinished(authSession, ctx));
    }

    /** A wallet holding BOTH the presented PID and a still-fresh card of ours must not be offered
     *  another. */
    @Test
    void holdingAFreshCardArmsNoOffer() throws Exception {
        IdentityProviderModel config = enabledConfig(false);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setAuthenticatedUser(new FakeUser());
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS,
            "[{\"vct\":\"urn:eudi:pid:1\",\"expiresAt\":null},"
          + "{\"vct\":\"" + OWN_VCT + "\",\"expiresAt\":" + (Instant.now().getEpochSecond() + 9_000_000L) + "}]");

        providerGranting(config, true).authenticationFinished(authSession, ctx);

        assertNull(authSession.clientNotes.get(Constants.KC_ACTION),
            "this device already has everything: no offer may interpose itself");
    }

    /** An unreadable CTX_CARDS note — a future format disagreement, say — must never turn an
     *  already proven login into an error page. */
    @Test
    void unreadableCardsNoteNeverCostsTheLogin() {
        IdentityProviderModel config = enabledConfig(false);
        FakeAuthenticationSession authSession = new FakeAuthenticationSession();
        authSession.setAuthenticatedUser(new FakeUser());
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("subject-1", config);
        ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, "[pas du json");

        assertDoesNotThrow(() ->
            providerGranting(config, true).authenticationFinished(authSession, ctx));
    }

    /**
     * {@code Oid4vpIdentityProvider} constructed with {@code session == null}, matching every other
     * test in this class (see class javadoc: real Keycloak-touching code is E2E-only), with
     * {@code createCardGrant} stubbed so the grant step doesn't need a session either.
     */
    private static Oid4vpIdentityProvider providerGranting(IdentityProviderModel config, boolean grantSucceeds) {
        return new Oid4vpIdentityProvider(null, config) {
            @Override
            protected CardGrant createCardGrant(String credentialConfigId) {
                return user -> grantSucceeds;
            }
        };
    }

    /**
     * The {@code client_id} announced to the wallet must be the fingerprint of the certificate that
     * signs the Request Object, and of nothing else. Deriving it from the hostname
     * ({@code x509_san_dns:}) breaks the moment the certificate carries no {@code dNSName}, which
     * is the case for the access certificate the EUDI registry issues: its SAN is a URI.
     */
    @Test
    void theClientIdIsTheFingerprintOfTheConfiguredSigningCertificate() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> raw = signingConfig(chain.issuerKeyPair, chain.issuerCert);
        Oid4vpConfig cfg = new Oid4vpConfig(raw);

        String clientId = Oid4vpIdentityProvider.clientId(signingMaterial(cfg));

        assertEquals(VerifierClientId.x509Hash(chain.issuerCert), clientId);
        assertTrue(clientId.startsWith("x509_hash:"), "the x509_san_dns scheme no longer applies");
    }

    /** Two distinct certificates cannot present under the same identity, or the fingerprint would
     *  prove nothing. */
    @Test
    void adifferentSigningCertificateYieldsADifferentClientId() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        Map<String, String> mine = signingConfig(chain.issuerKeyPair, chain.issuerCert);
        Map<String, String> other = signingConfig(chain.thirdPartyIssuerKeyPair, chain.thirdPartyIssuerCert);

        assertNotEquals(Oid4vpIdentityProvider.clientId(signingMaterial(new Oid4vpConfig(mine))),
            Oid4vpIdentityProvider.clientId(signingMaterial(new Oid4vpConfig(other))));
    }

    /**
     * The signing pair as a provider really carries it. Phase 1 makes both fields mandatory, so a
     * configuration holding a certificate and no key is one that cannot be saved.
     */
    private static Map<String, String> signingConfig(java.security.KeyPair pair,
                                                     java.security.cert.X509Certificate cert)
        throws Exception {
        Map<String, String> raw = baseConfig();
        raw.put(Oid4vpConfig.SIGNING_CERT_PEM, pem(cert.getEncoded()));
        raw.put(Oid4vpConfig.SIGNING_KEY_PEM, "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pair.getPrivate().getEncoded())
            + "\n-----END PRIVATE KEY-----\n");
        return raw;
    }

    /**
     * Resolves through the real resolver with an empty realm, so these assertions also cover the
     * fallback path: a provider naming no key component still signs with its pasted pair.
     */
    private static VerifierSigningMaterial signingMaterial(Oid4vpConfig cfg) {
        return VerifierSigningMaterial.resolve(cfg, java.util.stream.Stream::of);
    }

    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n"
            + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
            + "\n-----END CERTIFICATE-----\n";
    }

    private static IdentityProviderModel enabledConfig(boolean transientUsers) {
        IdentityProviderModel config = new IdentityProviderModel();
        config.setEnabled(true); // BrokeredIdentityContext's constructor refuses a disabled provider
        // setConfig() REPLACES the whole map, so it must come before setTransientUsers() — which
        // writes its "doNotStoreUsers" flag into that same map — or the flag is silently wiped out.
        config.setConfig(baseConfig());
        config.setTransientUsers(transientUsers);
        return config;
    }

    private static Map<String, String> baseConfig() {
        Map<String, String> raw = new HashMap<>();
        raw.put(Oid4vpConfig.OWN_VCT, OWN_VCT);
        raw.put(Oid4vpConfig.OWN_CREDENTIAL_CONFIG_ID, CREDENTIAL_CONFIG_ID);
        return raw;
    }

    /**
     * A hand-written {@link UserModel}. Only {@code getFirstAttribute} and
     * {@code setSingleAttribute} are backed by a real map — what {@code authenticationFinished}
     * actually touches; the rest of this wide SPI interface is a no-op, there being no mock
     * framework on the test classpath.
     */
    private static final class FakeUser implements UserModel {
        final Map<String, String> attributes = new HashMap<>();
        /** Counts {@link #setSingleAttribute} calls, so a test can check that an ordinary login
         *  writes nothing. */
        int setSingleAttributeCalls = 0;
        /** When non-null, {@link #setSingleAttribute} throws it instead of writing, which pins the
         *  "a write must never cost the login" net without relying on an accidental side effect. */
        RuntimeException setSingleAttributeThrows;

        @Override public String getFirstAttribute(String name) { return attributes.get(name); }
        @Override public void setSingleAttribute(String name, String value) {
            setSingleAttributeCalls++;
            if (setSingleAttributeThrows != null) {
                throw setSingleAttributeThrows;
            }
            attributes.put(name, value);
        }
        @Override public void setAttribute(String name, List<String> values) {
            attributes.put(name, values.isEmpty() ? null : values.get(0));
        }
        @Override public void removeAttribute(String name) { attributes.remove(name); }
        @Override public Stream<String> getAttributeStream(String name) {
            String value = attributes.get(name);
            return value == null ? Stream.empty() : Stream.of(value);
        }
        @Override public Map<String, List<String>> getAttributes() {
            // setAttribute can store null, and List.of(v) would then throw an NPE the day a test
            // called getAttributes() after such a call. List.of() for an absent value, never
            // List.of(null).
            Map<String, List<String>> result = new HashMap<>();
            attributes.forEach((k, v) -> result.put(k, v == null ? List.of() : List.of(v)));
            return result;
        }
        @Override public String getId() { return "fake-user-1"; }
        @Override public String getUsername() { return "fake-user"; }
        @Override public void setUsername(String username) { }
        @Override public Long getCreatedTimestamp() { return null; }
        @Override public void setCreatedTimestamp(Long timestamp) { }
        @Override public boolean isEnabled() { return true; }
        @Override public void setEnabled(boolean enabled) { }
        @Override public Stream<String> getRequiredActionsStream() { return Stream.empty(); }
        @Override public void addRequiredAction(String action) { }
        @Override public void removeRequiredAction(String action) { }
        @Override public String getFirstName() { return null; }
        @Override public void setFirstName(String firstName) { }
        @Override public String getLastName() { return null; }
        @Override public void setLastName(String lastName) { }
        @Override public String getEmail() { return null; }
        @Override public void setEmail(String email) { }
        @Override public boolean isEmailVerified() { return false; }
        @Override public void setEmailVerified(boolean verified) { }
        @Override public Stream<GroupModel> getGroupsStream() { return Stream.empty(); }
        @Override public void joinGroup(GroupModel group) { }
        @Override public void leaveGroup(GroupModel group) { }
        @Override public boolean isMemberOf(GroupModel group) { return false; }
        @Override public String getFederationLink() { return null; }
        @Override public void setFederationLink(String link) { }
        @Override public String getServiceAccountClientLink() { return null; }
        @Override public void setServiceAccountClientLink(String clientInternalId) { }
        @Override public SubjectCredentialManager credentialManager() { return null; }
        @Override public Stream<RoleModel> getRealmRoleMappingsStream() { return Stream.empty(); }
        @Override public Stream<RoleModel> getClientRoleMappingsStream(ClientModel client) { return Stream.empty(); }
        @Override public boolean hasRole(RoleModel role) { return false; }
        @Override public void grantRole(RoleModel role) { }
        @Override public Stream<RoleModel> getRoleMappingsStream() { return Stream.empty(); }
        @Override public void deleteRoleMapping(RoleModel role) { }
    }

    /** Minimal hand-rolled {@link AuthenticationSessionModel}: only client/user-session notes are
     *  backed by real maps (what {@code authenticationFinished} actually touches); everything else
     *  in this large SPI interface is a no-op/null, since no mocking framework is on the test
     *  classpath and authenticationFinished never calls it. */
    private static final class FakeAuthenticationSession implements AuthenticationSessionModel {
        final Map<String, String> clientNotes = new HashMap<>();
        final Map<String, String> userSessionNotes = new HashMap<>();
        final Map<String, String> authNotes = new HashMap<>();
        UserModel authenticatedUser;
        /** {@code ClientModel} is far too wide to hand-write and there is no mock framework on the
         *  classpath, so a dynamic proxy answering {@code getClientId()} alone suffices: it is the
         *  only method {@code authenticationFinished} calls. */
        ClientModel client = (ClientModel) java.lang.reflect.Proxy.newProxyInstance(
            ClientModel.class.getClassLoader(), new Class<?>[] {ClientModel.class},
            (proxy, method, args) -> "getClientId".equals(method.getName()) ? LOGIN_CLIENT_ID : null);

        @Override public String getTabId() { return "tab"; }
        @Override public RootAuthenticationSessionModel getParentSession() { return null; }
        @Override public Map<String, CommonClientSessionModel.ExecutionStatus> getExecutionStatus() { return Map.of(); }
        @Override public void setExecutionStatus(String authenticator, CommonClientSessionModel.ExecutionStatus status) { }
        @Override public void clearExecutionStatus() { }
        @Override public UserModel getAuthenticatedUser() { return authenticatedUser; }
        @Override public void setAuthenticatedUser(UserModel user) { this.authenticatedUser = user; }
        @Override public Set<String> getRequiredActions() { return new HashSet<>(); }
        @Override public void addRequiredAction(String action) { }
        @Override public void removeRequiredAction(String action) { }
        @Override public void addRequiredAction(UserModel.RequiredAction action) { }
        @Override public void removeRequiredAction(UserModel.RequiredAction action) { }
        @Override public void setUserSessionNote(String name, String value) { userSessionNotes.put(name, value); }
        @Override public Map<String, String> getUserSessionNotes() { return userSessionNotes; }
        @Override public void clearUserSessionNotes() { userSessionNotes.clear(); }
        @Override public String getAuthNote(String name) { return authNotes.get(name); }
        @Override public void setAuthNote(String name, String value) { authNotes.put(name, value); }
        @Override public void removeAuthNote(String name) { authNotes.remove(name); }
        @Override public void clearAuthNotes() { authNotes.clear(); }
        @Override public String getClientNote(String name) { return clientNotes.get(name); }
        @Override public void setClientNote(String name, String value) { clientNotes.put(name, value); }
        @Override public void removeClientNote(String name) { clientNotes.remove(name); }
        @Override public Map<String, String> getClientNotes() { return clientNotes; }
        @Override public void clearClientNotes() { clientNotes.clear(); }
        @Override public Set<String> getClientScopes() { return new HashSet<>(); }
        @Override public void setClientScopes(Set<String> clientScopes) { }
        @Override public String getRedirectUri() { return null; }
        @Override public void setRedirectUri(String uri) { }
        @Override public RealmModel getRealm() { return null; }
        @Override public ClientModel getClient() { return client; }
        @Override public String getAction() { return null; }
        @Override public void setAction(String action) { }
        @Override public String getProtocol() { return null; }
        @Override public void setProtocol(String protocol) { }
    }
}
