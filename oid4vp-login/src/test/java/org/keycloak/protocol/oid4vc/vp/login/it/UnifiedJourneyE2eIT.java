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
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
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
 * <b>The unified journey.</b> ONE request, posed once and for all, asks for the PID and our own card
 * as two optional sets — and the server infers from the response who is in front of it, without
 * consulting server state or guessing before it has asked the wallet.
 *
 * <p>Five scenarios:</p>
 * <ol>
 *   <li>an unknown holder with a PID alone: they sign in, the account is created, a card is
 *       offered;</li>
 *   <li>signing in again with BOTH: the same account, <b>no offer interposes itself</b>, and the
 *       token carries a {@code verified_claims} <b>array</b> of two entries with distinct
 *       frameworks;</li>
 *   <li>our card alone: straight in;</li>
 *   <li>an expired card plus a PID: in, the expired card discarded, a fresh one <b>re-offered</b>.
 *       This is the case that justifies the whole design — it was not distinguishable before;</li>
 *   <li>a trusted third-party issuer forging our own credential, which pinning refuses.</li>
 * </ol>
 *
 * <p>Deliberately self-contained: it repeats {@code CardLifecycleE2eIT}'s HTTP helpers rather than
 * introduce a test class hierarchy coupling four containers' lifetimes.</p>
 *
 * <p><b>What is ABSENT is the demonstration.</b> There is no {@code useDcql} and no
 * {@code setIdpConfig} here: the unified DCQL is set once, at realm import, and no scenario changes
 * it. The earlier tests switch the query between their scenarios — that switching is exactly what
 * this design removes.</p>
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UnifiedJourneyE2eIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String REALM = "oid4vp-test";
    private static final String CLIENT_ID = "test-app";
    private static final String CLIENT_SECRET = "test-app-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/callback";
    private static final String IDP_ALIAS = "oid4vp";

    private static final String PID_VCT = "urn:eudi:pid:1";
    private static final String VCT = "urn:pn:account-holder:1";
    private static final String CONFIG_ID = "account-holder";
    private static final String FEDID_ATTRIBUTE = ClaimsToContext.FEDID_ATTRIBUTE;

    /** The CARD's lifetime ({@code vc.refresh_interval_in_seconds}): 90 days, well beyond the
     *  realm's 30-day re-offer threshold. Without that gap a freshly issued card would ALREADY be
     *  "close to expiry", an offer would interpose itself at every login, and scenarios 2 and 3
     *  would be unobservable. */
    private static final long CARD_LIFETIME_SECONDS = 7776000L;
    /** Horizon du DROIT d'obtenir des cartes ({@code vc.expiry_in_seconds}) : 1 an. */
    private static final long ENTITLEMENT_SECONDS = 31536000L;

    /** Link 6's INFO log: direct evidence that a presentation was DISCARDED for expiry rather
     *  than failing the whole transaction. Only scenario 4 can produce it, and it runs last. */
    private static final String DISCARD_LOG = "Discarding the presentation returned under key";

    /**
     * <b>The unified query.</b> Two OPTIONAL sets, one per type — not two options of one set: with
     * options, a "PID" response would stay irreducibly ambiguous (a new holder, a reset phone, or a
     * holder who has both), and DCQL offers no way to prioritise between options.
     *
     * <p>Both queries ask for {@code sub} EXPLICITLY. The subject comes out as a <b>disclosure</b>,
     * so a silent query would only work through the simulated wallet's complacency: a wallet
     * genuinely honouring selective disclosure would reveal nothing and the login would be refused.
     * Same reason for {@code email}, which {@code matchingClaim} names.</p>
     */
    private static final String UNIFIED_DCQL = """
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
           "claims":[{"path":["sub"]},{"path":["email"]},{"path":["given_name"]},
                     {"path":["family_name"]},{"path":["age_over_18"]}]},
          {"id":"own","format":"dc+sd-jwt","meta":{"vct_values":["urn:pn:account-holder:1"]},
           "claims":[{"path":["sub"]}]}],
         "credential_sets":[
          {"required":false,"options":[["pid"]]},
          {"required":false,"options":[["own"]]}]}""";

    private static final String KEYSTORE_PASSWORD = "changeit";
    private static final String KEYSTORE_ALIAS = "card-issuer";
    /** Imposed by Keycloak: a realm keystore must live under
     *  {@code ${kc.home.dir}/data/{realm}/}, or the server refuses to start. */
    private static final String KEYSTORE_PATH = "/opt/keycloak/data/oid4vp-test/card-issuer.p12";

    /** The account created in scenario 1: the one scenarios 2 and 3 must land back on. */
    private static String FIRST_ACCOUNT_ID;
    /** Scenario 1's wallet, once it holds both the PID and our card. */
    private static SimulatedWallet FIRST_WALLET;

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
        Path realmFile = writeRealmImport();
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
            Files.writeString(Paths.get(System.getProperty("user.dir"), "target", "kc-unified.log"), content);
        } catch (Exception ignored) {
            // best effort
        }
    }

    /** The Keycloak container's log, as it stands at this instant. */
    private static String keycloakLogs() {
        try {
            return keycloak.getLogs();
        } catch (Exception e) {
            return KC_LOGS.toUtf8String();
        }
    }

    // ---- scenarios --------------------------------------------------------------

    /**
     * An UNKNOWN holder arrives with their PID alone, under the unified query. The account is
     * created and the card this Keycloak issues is offered to them: the bootstrap every following
     * scenario depends on.
     */
    @Test
    @Order(1)
    void anUnknownHolderLogsInWithThePidAloneAndReceivesACard() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        final String email = "unifie@example.org";
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-UNIFIE-1", "email", email, "given_name", "Ulysse",
                   "family_name", "Unified", "age_over_18", true), PID_VCT);

        assertEquals(0, usersByEmail(bearer, email).size(), "this holder must be UNKNOWN");

        String offerPage = loginUntilOfferPage(browser, "e2e-unifie-1", wallet);
        wallet.receive(VCT, new Oid4vciClient(HttpClient.newHttpClient())
            .fetchCredential(Oid4vciClient.offerUriFromWalletUri(offerLinkOf(offerPage)),
                wallet.holderKeyPair()));
        assertTrue(wallet.holds(VCT), "the wallet must hold the card it just received");
        assertTrue(submitOfferForm(browser, offerPage, false).contains("code="),
            "the first login must reach an authorization code");

        JsonNode users = usersByEmail(bearer, email);
        assertEquals(1, users.size(), "first-broker-login must have created the account, response=" + users);
        FIRST_ACCOUNT_ID = users.get(0).get("id").asText();
        FIRST_WALLET = wallet;
    }

    /**
     * The holder returns with BOTH cards on the same device. No offer may interpose itself, since
     * they already have everything; the identity comes from OUR card; and the token must carry a
     * {@code verified_claims} ARRAY, each assertion staying attributed to the card carrying it,
     * with its own trust framework.
     */
    @Test
    @Order(2)
    void presentingBothLandsOnTheSameAccountWithoutAnyOfferAndEmitsAnArray() throws Exception {
        assertNotNull(FIRST_WALLET, "scenario 1 must have succeeded: it supplies the wallet");
        HttpClient browser = newBrowser();
        LoginOutcome outcome = runWalletLogin(browser, "e2e-unifie-2", FIRST_WALLET);

        assertEquals("completed", outcome.terminalStatus());
        assertNotNull(outcome.code(),
            "no offer may interpose itself: this device already has everything, body="
                + snippet(outcome.body()));

        JsonNode idToken = decodeJwtPayload(exchangeCode(outcome.code()).get("id_token").asText());
        // Both cards carry the SAME federated identifier — ours was issued from the PID's — so this
        // assertion does not say WHICH founded the identity. It says presenting both fabricates no
        // second account. Scenario 3 is what proves our card alone founds that identity.
        assertEquals(FIRST_ACCOUNT_ID, idToken.path("sub").asText(),
            "presenting both must land on the SAME account as the bootstrap, never create a second");

        JsonNode verifiedClaims = idToken.path("verified_claims");
        assertTrue(verifiedClaims.isArray(),
            "two presentations -> an ARRAY of two entries (OIDC4IDA), payload="
                + snippet(idToken.toString()));
        assertEquals(2, verifiedClaims.size(),
            "one entry per verified presentation, payload=" + snippet(idToken.toString()));
        Set<String> frameworks = new HashSet<>();
        verifiedClaims.forEach(e -> frameworks.add(
            e.path("verification").path("trust_framework").asText()));
        assertEquals(Set.of("eidas", "pn_account_possession"), frameworks,
            "each assertion stays attributed to the card carrying it: our card is a possession "
                + "factor and must NEVER be announced as eidas");
    }

    /**
     * A wallet holding nothing but OUR card, the PID removed: the same unified query, one key in
     * the response, and straight in on the same account.
     */
    @Test
    @Order(3)
    void ourCardAloneLogsInDirectly() throws Exception {
        assertNotNull(FIRST_WALLET, "scenario 1 must have succeeded: it supplies the card to hand over");
        SimulatedWallet cardOnly = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "IGNORED"), "urn:no:pid");       // forges no PID at all
        cardOnly.adoptHolderKeyOf(FIRST_WALLET);           // the card is bound by cnf to ITS key
        cardOnly.receive(VCT, FIRST_WALLET.credentialOf(VCT));

        LoginOutcome outcome = runWalletLogin(newBrowser(), "e2e-unifie-3", cardOnly);

        assertEquals("completed", outcome.terminalStatus(),
            "presenting our card alone must verify, body=" + snippet(outcome.body()));
        assertNotNull(outcome.code(), "our card alone must sign in directly, body="
            + snippet(outcome.body()));

        JsonNode idToken = decodeJwtPayload(exchangeCode(outcome.code()).get("id_token").asText());
        assertEquals(FIRST_ACCOUNT_ID, idToken.path("sub").asText(),
            "our card carries the bootstrap's federated identifier: the same account, with no PID");
        assertFalse(idToken.path("verified_claims").isArray(),
            "one presentation -> the OBJECT, not an array, payload=" + snippet(idToken.toString()));
        assertEquals("pn_account_possession",
            idToken.path("verified_claims").path("verification").path("trust_framework").asText(),
            "only our card was presented: nothing eidas may be announced, payload="
                + snippet(idToken.toString()));
    }

    /**
     * <b>The case that justifies the design.</b> The holder presents both cards, but ours has
     * EXPIRED: it is discarded at link 6, the PID authenticates onto the SAME account, and a fresh
     * card is re-offered.
     *
     * <p>This situation used not to be distinguishable: an expired card failed the whole
     * transaction, or the query never asked for both at once.</p>
     */
    @Test
    @Order(4)
    void anExpiredCardIsDiscardedThePidLogsInAndACardIsOfferedAgain() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        final String email = "expiree@example.org";
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-EXPIRE-1", "email", email, "given_name", "Éva",
                   "family_name", "Expired", "age_over_18", true), PID_VCT);

        // Bootstrap: the account exists and carries oid4vp.fedid. The offered card is NOT collected
        // — this wallet will instead receive a card of the same type, but expired.
        String offerPage = loginUntilOfferPage(browser, "e2e-unifie-4a", wallet);
        assertTrue(submitOfferForm(browser, offerPage, false).contains("code="),
            "this scenario's bootstrap must reach an authorization code");
        JsonNode users = usersByEmail(bearer, email);
        assertEquals(1, users.size(), "the bootstrap must have created the account, response=" + users);
        JsonNode account = users.get(0);
        JsonNode fedidValues = account.path("attributes").path(FEDID_ATTRIBUTE);
        assertTrue(fedidValues.isArray() && !fedidValues.isEmpty(),
            "le compte doit porter " + FEDID_ATTRIBUTE + " (cf. unmanagedAttributePolicy), compte="
                + snippet(account.toString()));
        String fedid = fedidValues.get(0).asText();
        assertFalse(wallet.holds(VCT), "this wallet must hold no valid card of ours");

        // The wallet holds a card of OUR type, with the right subject, but EXPIRED. Forged by the
        // test chain — the same authority as the realm's issuance keystore — so indistinguishable to
        // the verifier until link 6, which is precisely the point under test.
        long now = Instant.now().getEpochSecond();
        wallet.receive(VCT, new TestCredentialIssuer(chain).issue(VCT, Map.of("sub", fedid),
            wallet.holderKeyPair().getPublic(), now - 100_000, now - 10));
        assertFalse(keycloakLogs().contains(DISCARD_LOG),
            "no earlier scenario presents an expired card: the log must not carry link 6's trace "
                + "yet");

        // The case itself: both are presented, the expired card is discarded with a log entry, the
        // PID authenticates, and a fresh card is re-offered.
        String secondOffer = loginUntilOfferPage(browser, "e2e-unifie-4b", wallet);
        assertTrue(secondOffer.contains("credential-offer-uri-link"),
            "a fresh card must be re-offered, body=" + snippet(secondOffer));

        // DIRECT evidence of link 6: the expired presentation was DISCARDED, not fatal. Without
        // this observation, "the PID signed in" would stay compatible with "the expired card was
        // never presented at all".
        assertTrue(keycloakLogs().contains(DISCARD_LOG),
            "the log must carry the trace of the presentation discarded for expiry");

        JsonNode idToken = decodeJwtPayload(exchangeCode(extract(
            submitOfferForm(browser, secondOffer, false), "[?&]code=([^&]+)"))
            .get("id_token").asText());
        assertEquals(account.get("id").asText(), idToken.path("sub").asText(),
            "with the expired card discarded, the PID founds the identity — and lands on the SAME "
                + "account as the bootstrap");

        // A corollary of discarding: the expired card attested nothing at all. One presentation
        // survived, so the OBJECT rather than an array, and its framework is the PID's.
        JsonNode verifiedClaims = idToken.path("verified_claims");
        assertFalse(verifiedClaims.isArray(),
            "the expired card must attest nothing: one entry, payload="
                + snippet(idToken.toString()));
        assertEquals("eidas", verifiedClaims.path("verification").path("trust_framework").asText(),
            "only the PID was retained, payload=" + snippet(idToken.toString()));
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
     * <b>The attack issuer pinning closes.</b> A perfectly legitimate third-party issuer — its
     * chain climbs to an anchor in {@code trustAnchorsPem} — forges a card bearing OUR {@code vct}
     * and an existing account's federated identifier.
     *
     * <p>Everything about it is sound: a valid signature, an approved chain, correct dates. Without
     * pinning the card would be accepted and its subject would become the federated identity
     * <em>verbatim</em>, letting the attacker into the victim's account.</p>
     *
     * <p>A security control exercised only by its passing cases is indistinguishable from a
     * {@code return true}: both are green. This test is the one that proves something.</p>
     */
    @Test
    @Order(5)
    void aTrustedThirdPartyIssuerCannotMintOurOwnCredential() throws Exception {
        HttpClient browser = newBrowser();
        String bearer = adminBearer();
        final String email = "usurpee@example.org";
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-USURPEE-1", "email", email, "given_name", "Alex",
                   "family_name", "Impersonated", "age_over_18", true), PID_VCT);

        // Bootstrap: the victim's account exists and carries its durable federated identifier.
        String offerPage = loginUntilOfferPage(browser, "e2e-usurpation-1", wallet);
        assertTrue(submitOfferForm(browser, offerPage, false).contains("code="),
            "this scenario's bootstrap must reach an authorization code");
        JsonNode users = usersByEmail(bearer, email);
        assertEquals(1, users.size(), "the bootstrap must have created the account, response=" + users);
        String fedid = users.get(0).path("attributes").path(FEDID_ATTRIBUTE).get(0).asText();

        // THE ATTACK. The card is signed by the approved THIRD PARTY's chain, not ours.
        long now = Instant.now().getEpochSecond();
        wallet.receive(VCT, new TestCredentialIssuer(chain).issueSignedBy(
            VCT, Map.of("sub", fedid), wallet.holderKeyPair().getPublic(),
            now - 60, now + 100_000,
            chain.thirdPartyIssuerKeyPair, chain.thirdPartyIssuerCert));

        LoginOutcome outcome = runWalletLogin(browser, "e2e-usurpation-2", wallet);

        // The fatal regime, not "discarded like an expired card": a forgery is not lifecycle
        // noise. Accepting the rest of a response containing one would mean ignoring what we did
        // not understand.
        assertEquals("failed", outcome.terminalStatus(),
            "a card of our type signed by a third party must fail the entire transaction");

        // AND FOR THE RIGHT REASON. `UNTRUSTED_ISSUER` would produce the same "failed": without
        // this second assertion the test would be green even if the third-party CA were not really
        // approved, proving "an unknown issuer is refused" — already true before pinning — instead
        // of "a KNOWN but unentitled issuer is refused".
        assertTrue(keycloakLogs().contains("not entitled to sign vct=" + VCT),
            "the refusal must come from entitlement, not from trust: the log must carry link 3a's "
                + "trace");
    }

    /**
     * Plays a complete login and stops on the OFFER PAGE: the application-initiated action
     * interposes itself between the end of authentication and the client redirect. Returns that
     * page's HTML.
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

    // ---- construction du realm --------------------------------------------------

    /**
     * Writes the realm to import, substituting the <b>unified</b> DCQL once and for all. No
     * scenario changes it afterwards — that is the demonstration.
     */
    private static Path writeRealmImport() throws Exception {
        String template;
        try (InputStream in = UnifiedJourneyE2eIT.class.getResourceAsStream("/realm-oid4vp-test.json")) {
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String realm = template
            .replace("@@CLIENT_SECRET@@", CLIENT_SECRET)
            // BOTH authorities are approved, which is the situation a trust registry will produce.
            // Only one is entitled to sign OUR type of card.
            .replace("@@TRUST_ANCHORS_PEM@@",
                jsonValue(pemCert(chain.caCert) + pemCert(chain.thirdPartyCaCert)))
            .replace("@@OWN_ISSUER_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@SIGNING_KEY_PEM@@", jsonValue(pemPkcs8(chain.issuerKeyPair.getPrivate().getEncoded())))
            .replace("@@SIGNING_CERT_PEM@@", jsonValue(pemCert(chain.issuerCert)))
            .replace("@@OWN_VCT@@", VCT)
            .replace("@@OWN_CREDENTIAL_CONFIG_ID@@", CONFIG_ID)
            .replace("@@DCQL_QUERY_JSON@@", jsonValue(UNIFIED_DCQL));

        Path file = Files.createTempFile("realm-oid4vp-unified", ".json");
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
