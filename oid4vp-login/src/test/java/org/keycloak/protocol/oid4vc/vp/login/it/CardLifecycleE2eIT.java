package org.keycloak.protocol.oid4vc.vp.login.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.keycloak.protocol.oid4vc.vp.login.protocol.ClaimsToContext;
import org.keycloak.protocol.oid4vc.vp.testsupport.Oid4vciClient;
import org.keycloak.protocol.oid4vc.vp.testsupport.SimulatedWallet;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestCredentialIssuer;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.ToStringConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Proves, against a real Keycloak 26.7.2, that the card this Keycloak issues itself really does
 * sign its holder back in — the whole journey, end to end: sign in with a PID, the account is
 * created, the entitlement granted, the card offer displayed, the wallet receives the card, and
 * signing in again with OUR card lands on the SAME Keycloak account.
 *
 * <p>Four scenarios:</p>
 * <ol>
 *   <li>bootstrap, then signing in again with our card;</li>
 *   <li>the holder declines the card, and the login still completes;</li>
 *   <li>a card close to expiry triggers a new offer;</li>
 *   <li>a revoked entitlement cuts the card off, and the account survives.</li>
 * </ol>
 *
 * <p>Deliberately self-contained: it repeats {@code WalletLoginE2eIT}'s HTTP helpers and
 * {@code CardIssuanceIT}'s issuance provisioning rather than introduce a test class hierarchy.
 * The three tests share no state and each starts its own container; a parent class would have
 * coupled three containers' lifetimes and made a passing test carry the risk of one still being
 * written.</p>
 *
 * <p><b>The lifetimes chosen here.</b> The card lives {@link #CARD_LIFETIME_SECONDS} (90 days)
 * while the realm's re-offer threshold is 30 days. Without that gap a freshly issued card would
 * ALREADY be "close to expiry" a second later, an offer would interpose itself at every login, and
 * scenario 1 could never observe an authorization code — nor scenario 3 prove anything, the offer
 * being the norm rather than the exception.</p>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CardLifecycleE2eIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String REALM = "oid4vp-test";
    private static final String CLIENT_ID = "test-app";
    private static final String CLIENT_SECRET = "test-app-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/callback";
    private static final String IDP_ALIAS = "oid4vp";

    private static final String VCT = "urn:pn:account-holder:1";
    private static final String CONFIG_ID = "account-holder";
    private static final String FEDID_ATTRIBUTE = ClaimsToContext.FEDID_ATTRIBUTE;

    /** The re-offer threshold the realm imports; one scenario raises it live, then restores it. */
    private static final String REISSUE_BEFORE_SECONDS = "2592000";
    /** The CARD's lifetime ({@code vc.refresh_interval_in_seconds}): 90 days, well beyond the
     *  30-day re-offer threshold — see the class javadoc. */
    private static final long CARD_LIFETIME_SECONDS = 7776000L;
    /** Horizon du DROIT d'obtenir des cartes ({@code vc.expiry_in_seconds}) : 1 an. */
    private static final long ENTITLEMENT_SECONDS = 31536000L;

    /** Le message que Keycloak affiche pour {@code Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR}
     *  the GENERIC external refusal message, the precise cause existing only in the server log.
     *  Its presence on the terminal page is what tells "the broker refused" apart from "some other
     *  page appeared". */
    private static final String BROKER_ERROR_MESSAGE =
        "Unexpected error when authenticating with identity provider";

    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "card-issuer";
    /** Imposed by Keycloak: a realm keystore must live under
     *  {@code ${kc.home.dir}/data/{realm}/}, or the server refuses to start. */
    private static final String KEYSTORE_PATH = "/opt/keycloak/data/oid4vp-test/card-issuer.p12";

    /** DCQL du bootstrap : un PID tiers, comme en phase 2a/3a. */
    private static final String PID_DCQL = """
        {"credentials":[{"id":"pid","format":"dc+sd-jwt",\
        "meta":{"vct_values":["urn:eudi:pid:1"]},\
        "claims":[{"path":["given_name"]},{"path":["age_over_18"]}]}]}""";

    /**
     * A DCQL asking only for our card, and asking EXPLICITLY for {@code sub}.
     *
     * <p>This entry used to declare no {@code claims} array, on the assumption that our card's
     * {@code sub} would be a VISIBLE claim and therefore impossible to request. That assumption is
     * wrong: the {@code sub} produced by {@code oid4vc-subject-id-mapper} comes out as a
     * <b>disclosure</b>, the default {@code visible_claims} carrying only
     * {@code id,iat,nbf,exp,jti}. A silent DCQL therefore held together only through the simulated
     * wallet's complacency, which presents a held card as is with every disclosure attached. A
     * wallet genuinely honouring selective disclosure would have revealed nothing,
     * {@code brokeredIdentityId} would have returned {@code null}, and signing in with our card
     * would have been refused. Asking for {@code sub} is mandatory, not optional.</p>
     */
    private static final String OWN_VCT_DCQL = "{\"credentials\":[{\"id\":\"own\","
        + "\"format\":\"dc+sd-jwt\",\"meta\":{\"vct_values\":[\"" + VCT + "\"]},"
        + "\"claims\":[{\"path\":[\"sub\"]}]}]}";

    private static TestTrustChain chain;
    private static GenericContainer<?> keycloak;
    private static String baseUrl;
    private static final ToStringConsumer KC_LOGS = new ToStringConsumer();

    /** A "browser" cookie jar: the broker plus AIA flow spans several navigations, and the
     *  authentication session survives only through these cookies. */
    private static final Map<String, String> COOKIES = new LinkedHashMap<>();

    /** An HTTP client OUTSIDE the browser session: the admin API and the token endpoint are called
     *  in the middle of a login in progress, and must neither share nor pollute the simulated
     *  browser's cookie jar. */
    private static final HttpClient BACKSTAGE = HttpClient.newHttpClient();

    @BeforeAll
    static void startKeycloak() throws Exception {
        chain = new TestTrustChain();
        Path realmFile = writeRealmImport(chain);
        Path keystoreFile = chain.writeCardIssuerKeystore(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);

        Path moduleDir = Paths.get(System.getProperty("user.dir"));
        Path loginJar = moduleDir.resolve("target/oid4vp-login-0.1.0-SNAPSHOT.jar");
        Path coreJar = moduleDir.resolve("../oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar").normalize();
        assertTrue(Files.isRegularFile(loginJar), "provider JAR absent (lancer via `verify`, pas `test`): " + loginJar);
        assertTrue(Files.isRegularFile(coreJar), "provider JAR absent (lancer via `verify`, pas `test`): " + coreJar);

        keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.7.2"))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forHostPath(coreJar.toString()),
                "/opt/keycloak/providers/oid4vp-core.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(loginJar.toString()),
                "/opt/keycloak/providers/oid4vp-login.jar")
            // mode 0644: temporary files are created 0600 by root, while the container
            // tourne en utilisateur "keycloak" (uid 1000) et doit pouvoir les lire.
            .withCopyFileToContainer(MountableFile.forHostPath(realmFile.toString(), 0644),
                "/opt/keycloak/data/import/realm-oid4vp-test.json")
            .withCopyFileToContainer(MountableFile.forHostPath(keystoreFile.toString(), 0644),
                KEYSTORE_PATH)
            .withCommand("start-dev", "--import-realm",
                "--features=oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer")
            .withLogConsumer(KC_LOGS)
            .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).forStatusCode(200)
                .withStartupTimeout(Duration.ofMinutes(3)));
        try {
            keycloak.start();
        } catch (RuntimeException e) {
            dumpLogs();
            throw e;
        }

        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);

        String bearer = adminBearer();
        // Keycloak 26 refuses "unmanaged" attributes by default; without this switch oid4vp.fedid,
        // which feeds the card's `sub`, would not be persisted.
        enableUnmanagedAttributes(bearer);
        createCredentialScope(bearer);
    }

    @AfterAll
    static void stopKeycloak() {
        dumpLogs();
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    private static void dumpLogs() {
        String content;
        try {
            content = keycloak != null ? keycloak.getLogs() : KC_LOGS.toUtf8String();
        } catch (Exception e) {
            content = KC_LOGS.toUtf8String();
        }
        try {
            Files.writeString(Paths.get(System.getProperty("user.dir"), "target", "kc-runtime.log"), content);
        } catch (Exception ignored) {
            // best effort
        }
    }

    // ---- scenarios --------------------------------------------------------------

    /**
     * An UNKNOWN holder signs in with their PID, receives OUR card, then signs in again presenting
     * it: they must land on the SAME Keycloak account, and the token must announce OUR card's trust
     * framework.
     *
     * <p>Obtaining the {@code UserModel} through {@code authSession.getAuthenticatedUser()} had only
     * ever been observed on the path of an ALREADY linked holder. The case that matters is the
     * opposite: an unknown holder at first enrolment. This test exercises it explicitly — no account
     * for that email before the login — and asserts that from that FIRST login the entitlement
     * exists on the freshly created account, so the grant really does reach first-broker-login.</p>
     */
    @Test
    @Order(1)
    void cardIssuedAtBootstrapLogsBackIntoTheSameAccount() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        useDcql(bearer, PID_DCQL);

        final String email = "card@example.org";
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-CARD-0001", "email", email,
                   "given_name", "Carla", "family_name", "Carte", "age_over_18", true));

        assertEquals(0, usersByEmail(bearer, email).size(),
            "this holder must be UNKNOWN before the first login: first-broker-login is what this "
                + "has to cover");

        // 1) Connexion par PID : la page d'offre doit s'intercaler AVANT la redirection client.
        String offerPageHtml = loginUntilOfferPage(browser, "e2e-card-1", wallet);

        // 1b) From this FIRST login the account exists AND carries the entitlement. Checked BEFORE
        //     the journey continues, so no admin call of this test could have granted it in the
        //     identity provider's place.
        JsonNode usersAfterFirst = usersByEmail(bearer, email);
        assertEquals(1, usersAfterFirst.size(),
            "first-broker-login must have created the account, response=" + usersAfterFirst);
        String userIdAfterFirst = usersAfterFirst.get(0).get("id").asText();
        JsonNode granted = entitlements(bearer, userIdAfterFirst);
        assertEquals(1, granted.size(),
            "the identity provider must grant the entitlement itself FROM an unknown holder's very "
                + "first login, or the offer it just armed would lead to a page that fails, response="
                + granted);

        // 2) The wallet receives the card, and the holder carries on.
        String offerUri = Oid4vciClient.offerUriFromWalletUri(offerLinkOf(offerPageHtml));
        String card = new Oid4vciClient(HttpClient.newHttpClient())
            .fetchCredential(offerUri, wallet.holderKeyPair());
        wallet.receive(VCT, card);
        assertTrue(wallet.holds(VCT), "the wallet must hold the card it received");

        String location = submitOfferForm(browser, offerPageHtml, false);
        assertTrue(location.contains("code="),
            "the first login must reach a code, location=" + location);

        // 3) Signing in again with OUR card: same identity provider alias, DCQL switched to our vct.
        useDcql(bearer, OWN_VCT_DCQL);
        LoginOutcome second = runWalletLogin(browser, "e2e-card-2", wallet);

        assertEquals("completed", second.terminalStatus());
        assertNotNull(second.code(), "the card WE issued must sign its holder in, location="
            + second.location() + " corps=" + snippet(second.body()));

        // 4) THE decisive assertion: which account did the SECOND login authenticate? The ID
        //    token's `sub` IS the authenticated user's Keycloak id — this realm declares no
        //    pairwise mapper — so it is the only observation this login directly influences.
        //
        //    This point used to be "proved" by a user search indexed on the email, a query the
        //    second login CANNOT influence. Had the durable identity link broken, our card — which
        //    carries NO email, the credential scope defining only the `card-subject` mapper and the
        //    DCQL asking only for `sub` — would have created a fresh account WITHOUT an email; the
        //    email search would have kept returning the original account with the right id, and both
        //    assertions would have passed while durable identity was broken.
        JsonNode idToken = decodeJwtPayload(exchangeCode(second.code()).get("id_token").asText());
        assertEquals(userIdAfterFirst, idToken.path("sub").asText(),
            "durable identity: signing in WITH OUR CARD must have authenticated the account created "
                + "at bootstrap, payload=" + snippet(idToken.toString()));

        assertEquals("pn_account_possession",
            idToken.path("verified_claims").path("verification").path("trust_framework").asText(),
            "our card is a possession factor: it must NEVER be announced as eidas, payload="
                + snippet(idToken.toString()));

        // 5) A corollary: no duplicate account was created along the way.
        JsonNode users = usersByEmail(bearer, email);
        assertEquals(1, users.size(), "no second account may be created, response=" + users);
        assertEquals(userIdAfterFirst, users.get(0).get("id").asText(),
            "the bootstrap account must have stayed the only holder of that email");
    }

    /** The holder declines the card, and the login completes anyway. */
    @Test
    @Order(2)
    void refusingTheOfferStillCompletesTheLogin() throws Exception {
        HttpClient browser = newBrowser();
        useDcql(adminBearer(), PID_DCQL);

        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-REFUS-0001", "email", "refus@example.org",
                   "given_name", "Renee", "family_name", "Declines", "age_over_18", true));

        String offerPageHtml = loginUntilOfferPage(browser, "e2e-card-refus", wallet);
        String location = submitOfferForm(browser, offerPageHtml, true);   // cancel-aia=true

        assertTrue(location.contains("code="),
            "declining the card must never cost the login: the holder has just proved their "
                + "identity, location=" + location);
        assertFalse(wallet.holds(VCT), "no card was collected in this scenario");
    }

    /**
     * A card close to expiry triggers a new offer.
     *
     * <p>The threshold is raised LIVE and restored in a {@code finally}: otherwise a later test
     * would inherit the raised threshold and see an offer where it expects a code. The same card is
     * presented first at the nominal threshold (no offer) and then at the raised one (offer): that
     * contrast, and not the mere appearance of a page, is what proves proximity to expiry decides.
     * </p>
     *
     * <p><b>Why that raised value.</b> {@code CARD_LIFETIME_SECONDS + 1}, and emphatically not a
     * giant one like 999,999,999 (about 31.7 years). Two distinct expiries are in play: the CARD's
     * {@code exp} at 90 days, and the ENTITLEMENT's {@code expiresAt} at one year. A giant
     * threshold exceeds both and the nominal 30 days is under both, so every combination would give
     * the same verdict whether
     * {@link org.keycloak.protocol.oid4vc.vp.login.card.ReofferRule} read the card's expiry or the
     * entitlement's — the test would stay green reading the wrong one. The value chosen sits
     * BETWEEN them, so it can only trigger the offer if the rule really compares against the card's
     * {@code exp}.</p>
     */
    @Test
    @Order(3)
    void aCardCloseToExpiryIsOfferedAgain() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        useDcql(bearer, PID_DCQL);

        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-RENEW-0001", "email", "renew@example.org",
                   "given_name", "Rita", "family_name", "Renouv", "age_over_18", true));

        String firstOffer = loginUntilOfferPage(browser, "e2e-card-renew-1", wallet);
        wallet.receive(VCT, new Oid4vciClient(HttpClient.newHttpClient())
            .fetchCredential(Oid4vciClient.offerUriFromWalletUri(offerLinkOf(firstOffer)),
                wallet.holderKeyPair()));
        submitOfferForm(browser, firstOffer, false);

        useDcql(bearer, OWN_VCT_DCQL);

        // The control: at the nominal 30-day threshold with a card living 90 days, signing in with
        // that same card must offer NOTHING. Without it, "an offer appeared" could equally well
        // mean "an offer always appears".
        LoginOutcome withoutUrgency = runWalletLogin(browser, "e2e-card-renew-witness", wallet);
        assertNotNull(withoutUrgency.code(),
            "far from expiry, the card must sign in with no offer interposing itself, body="
                + snippet(withoutUrgency.body()));

        setIdpConfig(bearer, "reissueBeforeSeconds", Long.toString(CARD_LIFETIME_SECONDS + 1));
        try {
            // Only the re-offer rule differs between the control above and this call: same wallet,
            // same held card, same DCQL.
            loginUntilOfferPage(browser, "e2e-card-renew-2", wallet);
        } finally {
            setIdpConfig(bearer, "reissueBeforeSeconds", REISSUE_BEFORE_SECONDS);
        }
    }

    /**
     * A revoked entitlement cuts the card off, and the account stays intact.
     *
     * <p>This test no longer settles for observing that no authorization code was delivered:
     * {@code assertNull(code)} is satisfied by ANY non-redirecting outcome — an offer page that
     * interposed itself, a template error, any failure at all — while being the assertion that
     * carries the revocation guarantee on its own. Two observations replace it, both specific to a
     * REFUSAL:</p>
     * <ul>
     *   <li>the terminal response really is the broker's error page, carrying the generic message
     *       {@code callback.error(..., IDENTITY_PROVIDER_UNEXPECTED_ERROR)} sets;</li>
     *   <li>no new user session was opened. That is the decisive observation: it depends on neither
     *       theme nor template, and tells "refused" apart from "something else happened". It is
     *       compared against the session count taken BEFORE the attempt, this scenario's own
     *       bootstrap having legitimately opened one.</li>
     * </ul>
     */
    @Test
    @Order(4)
    void revokedEntitlementNoLongerLogsInButAccountSurvives() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        useDcql(bearer, PID_DCQL);

        final String email = "revoked@example.org";
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-REVOKE-0001", "email", email,
                   "given_name", "Remi", "family_name", "Revoked", "age_over_18", true));

        String offerPage = loginUntilOfferPage(browser, "e2e-card-revoke-1", wallet);
        wallet.receive(VCT, new Oid4vciClient(HttpClient.newHttpClient())
            .fetchCredential(Oid4vciClient.offerUriFromWalletUri(offerLinkOf(offerPage)),
                wallet.holderKeyPair()));
        submitOfferForm(browser, offerPage, false);

        String userId = usersByEmail(bearer, email).get(0).get("id").asText();
        int sessionsBeforeRevocation = sessions(bearer, userId).size();
        revokeEntitlement(bearer, userId);

        useDcql(bearer, OWN_VCT_DCQL);
        LoginOutcome attempt = runWalletLogin(browser, "e2e-card-revoked", wallet);

        assertEquals("completed", attempt.terminalStatus(),
            "the card stays cryptographically valid: the refusal comes from the identity layer");
        assertNull(attempt.code(), "a card whose entitlement is revoked must deliver no code, "
            + "location=" + attempt.location());

        // "Refused", not merely "no code": the terminal response is the broker's error page with
        // its generic message — never the offer page, never some other page.
        assertNull(attempt.location(),
            "the refusal redirects nowhere: it renders a page, location=" + attempt.location());
        assertTrue(attempt.body().contains(BROKER_ERROR_MESSAGE),
            "the terminal response must be the broker's error page, body="
                + snippet(attempt.body()));
        assertFalse(attempt.body().contains("credential-offer-uri-link"),
            "and above all not an offer page: the entitlement has just been revoked, body="
                + snippet(attempt.body()));

        // And no session was opened along the way — the guarantee that "refused" means "not signed
        // in", whatever the page displays.
        assertEquals(sessionsBeforeRevocation, sessions(bearer, userId).size(),
            "the refused attempt must open NO session, sessions=" + sessions(bearer, userId));

        assertEquals(1, usersByEmail(bearer, email).size(),
            "revoking the entitlement does not touch the account");
    }

    // ---- the login journey ------------------------------------------------------

    /** The outcome of a complete wallet login: the transaction's terminal status, and whatever
     *  {@code complete/{tx}} led to — a client redirect, an offer page, or an error page. */
    private record LoginOutcome(String terminalStatus, HttpResponse<String> completed) {

        String location() {
            return completed.headers().firstValue("location").orElse(null);
        }

        String body() {
            return completed.body();
        }

        /** The authorization code the Location carries, or {@code null}. */
        String code() {
            String location = location();
            if (location == null) {
                return null;
            }
            Matcher m = Pattern.compile("[?&]code=([^&]+)").matcher(location);
            return m.find() ? m.group(1) : null;
        }
    }

    /**
     * Plays the complete wallet login flow — auth code with {@code kc_idp_hint}, QR page, Request
     * Object, direct_post presentation, polling, {@code complete/{tx}} — with the given wallet. It
     * starts from a clean browser session so every login repeats the whole journey instead of being
     * short-circuited by SSO.
     *
     * <p>The caller supplies the wallet rather than this method building one, because the wallet
     * carries the decisive state: the holder key and, once bootstrapped, the held card that
     * {@link SimulatedWallet#respondTo} then presents as is.</p>
     */
    private static LoginOutcome runWalletLogin(HttpClient browser, String state, SimulatedWallet wallet)
        throws Exception {
        COOKIES.clear();

        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=" + enc(state)
            + "&kc_idp_hint=" + IDP_ALIAS;
        HttpResponse<String> qrPage = follow(browser, authUrl, null);
        assertEquals(200, qrPage.statusCode(), "page QR attendue (200), corps=" + snippet(qrPage.body()));

        String html = qrPage.body();
        String statusUrl = extract(html, "var statusUrl = \"([^\"]+)\";");
        String completeUrl = extract(html, "var completeUrl = \"([^\"]+)\";");
        String tx = extract(statusUrl, "/status/([A-Za-z0-9_-]+)");
        String endpointBase = statusUrl.substring(0, statusUrl.indexOf("/status/"));

        HttpResponse<String> ro = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/request/" + tx))
                .header("Accept", "application/oauth-authz-req+jwt").GET());
        assertEquals(200, ro.statusCode(), "Request Object attendu (200)");

        String vpToken = wallet.respondTo(ro.body(), SimulatedWallet.Tamper.NONE);
        assertNotNull(vpToken, "le wallet doit produire un vp_token en Tamper.NONE");

        HttpResponse<String> posted = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/response/" + tx))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                    "response=" + enc(wallet.sealedResponse(vpToken, "A256GCM")))));
        assertEquals(200, posted.statusCode(), "direct_post attendu (200), corps=" + snippet(posted.body()));

        String terminalStatus = pollUntilTerminal(browser, statusUrl);

        // follow(..., REDIRECT_URI) ne rend une Location que si une redirection atteint le client —
        // the sole path by which an authorization code would be delivered. Any other outcome — an
        // AIA offer page, an error page — comes back here as a non-3xx response, body included.
        return new LoginOutcome(terminalStatus, follow(browser, completeUrl, REDIRECT_URI));
    }

    /**
     * Plays a complete login and stops on the OFFER PAGE: the application-initiated action
     * interposes itself between the end of authentication and the client redirect. Returns that
     * page's HTML.
     *
     * <p>Fails explicitly, and distinctly, if the login redirected straight to the client, meaning
     * the offer was NOT armed: "the offer page appeared" is never confused with "the login
     * completed".</p>
     */
    private static String loginUntilOfferPage(HttpClient browser, String state, SimulatedWallet wallet)
        throws Exception {
        LoginOutcome outcome = runWalletLogin(browser, state, wallet);
        assertEquals("completed", outcome.terminalStatus(),
            "the presentation must verify before an offer can interpose itself");
        assertNull(outcome.location(),
            "no offer interposed itself: the login went straight to the client (location="
                + outcome.location() + ") — the AIA was not armed, or not early enough");
        assertEquals(200, outcome.completed().statusCode(),
            "page d'offre attendue (200), corps=" + snippet(outcome.body()));
        assertTrue(outcome.body().contains("credential-offer-uri-link"),
            "la page rendue n'est pas la page d'offre de carte, corps=" + snippet(outcome.body()));
        return outcome.body();
    }

    /** The wallet URI ({@code openid-credential-offer://?credential_offer_uri=...}) that
     *  {@code oid4vc-credential-offer.ftl} renders in the clear. */
    private static String offerLinkOf(String offerPageHtml) {
        return unescapeHtml(extract(offerPageHtml,
            "<a href=\"([^\"]+)\"[^>]*id=\"credential-offer-uri-link\""));
    }

    /**
     * POST le formulaire de la page d'offre vers {@code url.loginAction}, en ajoutant
     * {@code cancel-aia=true} si {@code cancel}. Retourne la Location finale une fois les
     * redirections suivies jusqu'au client.
     *
     * <p>Le bouton « continuer » n'a pas d'attribut {@code name} dans le gabarit Keycloak : le
     * corps du POST est donc vide dans le cas nominal, et ne porte que {@code cancel-aia} sinon.</p>
     */
    private static String submitOfferForm(HttpClient browser, String offerPageHtml, boolean cancel)
        throws Exception {
        String action = unescapeHtml(extract(offerPageHtml,
            "<form action=\"([^\"]+)\"[^>]*id=\"kc-cred-offer-settings-form\""));
        HttpResponse<String> posted = exchange(browser,
            HttpRequest.newBuilder(URI.create(action))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "text/html")
                .POST(HttpRequest.BodyPublishers.ofString(cancel ? "cancel-aia=true" : "")));
        return followFrom(browser, posted, action, REDIRECT_URI);
    }

    // ---- administration du realm ------------------------------------------------

    /**
     * PUT {@code /admin/realms/{realm}/identity-provider/instances/oid4vp} en ne changeant qu'UNE
     * configuration key — read the representation, change it, write it back. Rewriting the whole
     * representation from a template would erase keys this test knows nothing about.
     */
    private static void setIdpConfig(String bearer, String key, String value) throws Exception {
        String url = baseUrl + "/admin/realms/" + REALM + "/identity-provider/instances/" + IDP_ALIAS;
        HttpResponse<String> current = backstage(HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, current.statusCode(), "GET idp attendu (200), corps=" + snippet(current.body()));

        ObjectNode idp = (ObjectNode) MAPPER.readTree(current.body());
        ((ObjectNode) idp.get("config")).put(key, value);

        HttpResponse<String> updated = backstage(HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(idp))));
        assertTrue(updated.statusCode() >= 200 && updated.statusCode() < 300,
            "PUT idp attendu (2xx), statut=" + updated.statusCode() + " corps=" + snippet(updated.body()));
    }

    /** Raccourci : {@code setIdpConfig(..., "dcqlQueryJson", dcqlJson)}. */
    private static void useDcql(String bearer, String dcqlJson) throws Exception {
        setIdpConfig(bearer, "dcqlQueryJson", dcqlJson);
    }

    /** This account's ENTITLEMENTS to obtain cards ({@code UserVerifiableCredentialModel}). */
    private static JsonNode entitlements(String bearer, String userId) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(
                URI.create(vcResource(userId) + "/credentials"))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "GET vc/credentials attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    /** DELETE {@code /admin/realms/{realm}/users/{id}/vc/credentials/{credentialScopeName}} → 204. */
    private static void revokeEntitlement(String bearer, String userId) throws Exception {
        HttpResponse<String> revoked = backstage(HttpRequest.newBuilder(
                URI.create(vcResource(userId) + "/credentials/" + enc(CONFIG_ID)))
            .header("Authorization", "Bearer " + bearer).DELETE());
        assertEquals(204, revoked.statusCode(),
            "expected the entitlement revocation (204), body=" + snippet(revoked.body()));
    }

    private static String vcResource(String userId) {
        return baseUrl + "/admin/realms/" + REALM + "/users/" + userId + "/vc";
    }

    /** Les sessions ouvertes pour ce compte ({@code GET /admin/realms/{realm}/users/{id}/sessions}) :
     *  a successful login creates one, a refused login creates none. */
    private static JsonNode sessions(String bearer, String userId) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/admin/realms/" + REALM + "/users/" + userId + "/sessions"))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "GET users/{id}/sessions attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    /** Les utilisateurs du realm ayant exactement cet email (via l'API d'administration). */
    private static JsonNode usersByEmail(String bearer, String email) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/admin/realms/" + REALM + "/users?email=" + enc(email) + "&exact=true"))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "liste des users admin attendue (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    /** Exchanges the authorization code at the token endpoint and returns the JSON response. */
    private static JsonNode exchangeCode(String code) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/realms/" + REALM + "/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + enc(CLIENT_SECRET))));
        assertEquals(200, r.statusCode(), "expected the code exchange (200), body=" + snippet(r.body()));
        return MAPPER.readTree(r.body());
    }

    /**
     * Creates our vct's credential scope and attaches it to {@code test-app} as an OPTIONAL scope.
     *
     * <p>Deliberately done through the admin API rather than in the realm template: declaring a
     * {@code clientScopes} array at import REPLACES Keycloak's built-in scopes
     * ({@code profile}, {@code email}, {@code roles}…), ce qui priverait de leurs claims tous les
     * tokens du realm.</p>
     */
    private static void createCredentialScope(String bearer) throws Exception {
        String scopeJson = """
            {
              "name": "%s",
              "description": "The account-holder card this Keycloak issues",
              "protocol": "oid4vc",
              "attributes": {
                "vc.credential_configuration_id": "%s",
                "vc.verifiable_credential_type": "%s",
                "vc.format": "dc+sd-jwt",
                "vc.credential_signing_alg": "ES256",
                "vc.expiry_in_seconds": "%d",
                "vc.refresh_interval_in_seconds": "%d",
                "vc.binding_required": "true",
                "vc.binding_required_proof_types": "jwt",
                "vc.cryptographic_binding_methods_supported": "jwk",
                "vc.include_in_metadata": "true",
                "include.in.token.scope": "true",
                "display.on.consent.screen": "false"
              },
              "protocolMappers": [
                {
                  "name": "card-subject",
                  "protocol": "oid4vc",
                  "protocolMapper": "oid4vc-subject-id-mapper",
                  "consentRequired": false,
                  "config": { "userAttribute": "%s", "claim.name": "id" }
                }
              ]
            }"""
            .formatted(CONFIG_ID, CONFIG_ID, VCT, ENTITLEMENT_SECONDS, CARD_LIFETIME_SECONDS,
                FEDID_ATTRIBUTE);
        HttpResponse<String> created = backstage(HttpRequest.newBuilder(
                URI.create(baseUrl + "/admin/realms/" + REALM + "/client-scopes"))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(scopeJson)));
        assertEquals(201, created.statusCode(),
            "expected the credential scope to be created (201), body=" + snippet(created.body()));

        HttpResponse<String> attached = backstage(HttpRequest.newBuilder(
                URI.create(baseUrl + "/admin/realms/" + REALM + "/clients/" + clientUuid(bearer)
                    + "/optional-client-scopes/" + clientScopeId(bearer, CONFIG_ID)))
            .header("Authorization", "Bearer " + bearer)
            .PUT(HttpRequest.BodyPublishers.noBody()));
        assertTrue(attached.statusCode() >= 200 && attached.statusCode() < 300,
            "expected the scope to attach to " + CLIENT_ID + " (2xx), status=" + attached.statusCode()
                + " body=" + snippet(attached.body()));
    }

    private static String clientUuid(String bearer) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/admin/realms/" + REALM + "/clients?clientId=" + enc(CLIENT_ID)))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "expected GET clients (200), body=" + snippet(r.body()));
        JsonNode clients = MAPPER.readTree(r.body());
        assertEquals(1, clients.size(), "client " + CLIENT_ID + " must exist, response=" + r.body());
        return clients.get(0).get("id").asText();
    }

    private static String clientScopeId(String bearer, String name) throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/admin/realms/" + REALM + "/client-scopes"))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, r.statusCode(), "GET client-scopes attendu (200), corps=" + snippet(r.body()));
        for (JsonNode scope : MAPPER.readTree(r.body())) {
            if (name.equals(scope.path("name").asText())) {
                return scope.get("id").asText();
            }
        }
        throw new IllegalStateException("client scope introuvable : " + name);
    }

    private static void enableUnmanagedAttributes(String bearer) throws Exception {
        String profileUrl = baseUrl + "/admin/realms/" + REALM + "/users/profile";
        HttpResponse<String> current = backstage(HttpRequest.newBuilder(URI.create(profileUrl))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, current.statusCode(), "GET users/profile: " + snippet(current.body()));

        ObjectNode profile = (ObjectNode) MAPPER.readTree(current.body());
        profile.put("unmanagedAttributePolicy", "ENABLED");

        HttpResponse<String> put = backstage(HttpRequest.newBuilder(URI.create(profileUrl))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(profile))));
        assertEquals(200, put.statusCode(), "PUT users/profile: " + put.statusCode() + " " + snippet(put.body()));
    }

    /** An admin access token (master realm, admin-cli) for the administration API. */
    private static String adminBearer() throws Exception {
        HttpResponse<String> r = backstage(HttpRequest.newBuilder(URI.create(baseUrl
                + "/realms/master/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(
                "grant_type=password&client_id=admin-cli&username=admin&password=admin")));
        assertEquals(200, r.statusCode(), "jeton admin attendu (200), corps=" + snippet(r.body()));
        return MAPPER.readTree(r.body()).get("access_token").asText();
    }

    // ---- helpers HTTP -----------------------------------------------------------

    private static HttpClient newBrowser() {
        COOKIES.clear();
        return HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    }

    /** A request OUTSIDE the browser session: no cookies sent, none collected. */
    private static HttpResponse<String> backstage(HttpRequest.Builder builder) throws Exception {
        return BACKSTAGE.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Follows redirects by hand, keeping cookies, until a non-3xx response — returned as is — or a
     * redirect whose Location starts with {@code stopPrefix}, returned unfollowed so the caller can
     * read it.
     */
    private static HttpResponse<String> follow(HttpClient http, String url, String stopPrefix) throws Exception {
        String current = url;
        for (int i = 0; i < 25; i++) {
            HttpResponse<String> r = exchange(http,
                HttpRequest.newBuilder(URI.create(current)).header("Accept", "text/html").GET());
            int sc = r.statusCode();
            if (sc >= 300 && sc < 400) {
                String loc = r.headers().firstValue("location")
                    .orElseThrow(() -> new IllegalStateException("redirection sans Location depuis " + url));
                String abs = URI.create(current).resolve(loc).toString();
                if (stopPrefix != null && abs.startsWith(stopPrefix)) {
                    return r;
                }
                current = abs;
            } else {
                return r;
            }
        }
        throw new IllegalStateException("trop de redirections depuis " + url);
    }

    /**
     * Continues a redirect chain from a response ALREADY obtained, typically a form POST, and
     * returns the first Location reaching {@code stopPrefix}.
     */
    private static String followFrom(HttpClient http, HttpResponse<String> response, String from,
                                      String stopPrefix) throws Exception {
        HttpResponse<String> current = response;
        String currentUrl = from;
        for (int i = 0; i < 25; i++) {
            int sc = current.statusCode();
            if (sc < 300 || sc >= 400) {
                return fail("attendait une redirection vers " + stopPrefix + ", statut=" + sc
                    + " url=" + currentUrl + " corps=" + snippet(current.body()));
            }
            String loc = current.headers().firstValue("location")
                .orElseThrow(() -> new IllegalStateException("redirection sans Location depuis " + from));
            String abs = URI.create(currentUrl).resolve(loc).toString();
            if (abs.startsWith(stopPrefix)) {
                return abs;
            }
            currentUrl = abs;
            current = exchange(http,
                HttpRequest.newBuilder(URI.create(abs)).header("Accept", "text/html").GET());
        }
        throw new IllegalStateException("trop de redirections depuis " + from);
    }

    private static String pollUntilTerminal(HttpClient http, String statusUrl) throws Exception {
        for (int i = 0; i < 30; i++) {
            HttpResponse<String> r = exchange(http,
                HttpRequest.newBuilder(URI.create(statusUrl)).header("Accept", "application/json").GET());
            String status = MAPPER.readTree(r.body()).path("status").asText();
            if (!"pending".equals(status)) {
                return status;
            }
            Thread.sleep(300);
        }
        return "pending";
    }

    /**
     * Sends a request with every remembered cookie, and harvests the response's
     * {@code Set-Cookie}; a cookie with an empty or deleted value is dropped from the jar.
     */
    private static HttpResponse<String> exchange(HttpClient http, HttpRequest.Builder builder) throws Exception {
        if (!COOKIES.isEmpty()) {
            builder.header("Cookie", COOKIES.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .collect(Collectors.joining("; ")));
        }
        HttpResponse<String> r = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        for (String setCookie : r.headers().allValues("set-cookie")) {
            String pair = setCookie.split(";", 2)[0].trim();
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = pair.substring(0, eq);
            String value = pair.substring(eq + 1);
            if (value.isEmpty()) {
                COOKIES.remove(name);
            } else {
                COOKIES.put(name, value);
            }
        }
        return r;
    }

    /** Decodes a compact JWT's payload — the second, base64url segment — into JSON. */
    private static JsonNode decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length, "expected a compact JWT of 3 segments, got=" + parts.length);
        return MAPPER.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
    }

    // ---- realm construction -----------------------------------------------------

    /** This container ENABLES issuance: the complete issuance journey is what it exercises. See
     *  {@code WalletLoginE2eIT.writeRealmImport} for why each test declares this rather than the
     *  shared template hard-coding it. */
    private static Path writeRealmImport(TestTrustChain chain) throws Exception {
        String template;
        try (InputStream in = CardLifecycleE2eIT.class.getResourceAsStream("/realm-oid4vp-test.json")) {
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String realm = template
            .replace("@@CLIENT_SECRET@@", CLIENT_SECRET)
            .replace("@@TRUST_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@OWN_ISSUER_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@SIGNING_KEY_PEM@@", jsonValue(pemPkcs8(chain.issuerKeyPair.getPrivate().getEncoded())))
            .replace("@@SIGNING_CERT_PEM@@", jsonValue(pemCert(chain.issuerCert)))
            .replace("@@OWN_VCT@@", VCT)
            .replace("@@OWN_CREDENTIAL_CONFIG_ID@@", CONFIG_ID)
            .replace("@@DCQL_QUERY_JSON@@", jsonValue(PID_DCQL));

        Path file = Files.createTempFile("realm-oid4vp-lifecycle", ".json");
        Files.writeString(file, realm, StandardCharsets.UTF_8);
        return file;
    }

    /** Escapes a value for insertion into a JSON string, without the outer quotes. */
    private static String jsonValue(String raw) throws Exception {
        String quoted = MAPPER.writeValueAsString(raw);
        return quoted.substring(1, quoted.length() - 1);
    }

    private static String pemCert(X509Certificate cert) throws Exception {
        return pem("CERTIFICATE", cert.getEncoded());
    }

    private static String pemPkcs8(byte[] der) {
        return pem("PRIVATE KEY", der);
    }

    private static String pem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    // ---- petits utilitaires -----------------------------------------------------

    private static String extract(String source, String regex) {
        Matcher m = Pattern.compile(regex).matcher(source);
        if (!m.find()) {
            fail("motif introuvable [" + regex + "] dans : " + snippet(source));
        }
        return m.group(1);
    }

    /** Keycloak's Freemarker templates escape HTML attributes, so an HTTP client must restore the
     *  original characters before replaying the URL. */
    private static String unescapeHtml(String value) {
        return value.replace("&amp;", "&").replace("&#61;", "=").replace("&quot;", "\"");
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String snippet(String s) {
        if (s == null) {
            return "<null>";
        }
        return s.length() > 900 ? s.substring(0, 900) + "..." : s;
    }
}
