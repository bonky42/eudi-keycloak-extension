package org.keycloak.protocol.oid4vc.vp.login.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
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
 * Drives the COMPLETE OID4VP brokered login flow against a real Keycloak 26.7.2 carrying our
 * providers.
 *
 * <p>{@code maven-failsafe-plugin} runs this in the {@code integration-test} phase, so after
 * {@code package}: the reactor's jars exist in their {@code target/} directories and are copied
 * into the container's {@code /opt/keycloak/providers/} through
 * {@link GenericContainer#withCopyFileToContainer} — a byte-stream copy through the docker API,
 * independent of host paths and therefore fine when running in a sibling container.</p>
 *
 * <p>The realm is built dynamically: this run's {@link TestTrustChain} keys are injected as PEM
 * into the {@code realm-oid4vp-test.json} template, so the {@link SimulatedWallet} issues
 * credentials signed by the anchor the {@code oid4vp} identity provider trusts.</p>
 */
class WalletLoginE2eIT {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String REALM = "oid4vp-test";
    private static final String CLIENT_ID = "test-app";
    private static final String CLIENT_SECRET = "test-app-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/callback";

    private static final String EMAIL = "marie@example.org";
    private static final String GIVEN_NAME = "Marie";
    private static final String FAMILY_NAME = "Curie";
    /** The persistent identifier the test PID carries, named by {@code subjectClaim}. */
    private static final String SUBJECT = "PID-MARIE-0001";

    /** Identities dedicated to the durable-identity tests, with distinct emails for isolated
     *  admin assertions. */
    private static final String RELOGIN_EMAIL = "relogin@example.org";
    private static final String RELOGIN_SUBJECT = "PID-RELOGIN-0002";
    private static final String NO_SUBJECT_EMAIL = "no-subject@example.org";

    /** An ordinary password user of the same realm: the control case, with no presentation. */
    private static final String PWD_USERNAME = "pwd-user";
    private static final String PWD_EMAIL = "pwd-user@example.org";
    private static final String PWD_PASSWORD = "pwd-secret";

    private static final String FORMAT = "dc+sd-jwt";

    private static final String DCQL_QUERY_JSON = """
        {"credentials":[{"id":"pid","format":"dc+sd-jwt",\
        "meta":{"vct_values":["urn:eudi:pid:1"]},\
        "claims":[{"path":["given_name"]},{"path":["age_over_18"]}]}]}""";
    private static final String VCT = "urn:eudi:pid:1";

    private static TestTrustChain chain;
    private static GenericContainer<?> keycloak;
    private static String baseUrl;
    private static final ToStringConsumer KC_LOGS = new ToStringConsumer();

    /** A "browser" cookie jar. Java's CookieManager handles Keycloak's cookies poorly (Path and
     *  SameSite attributes), so they are managed by hand: every cookie of the same host is sent
     *  with every request, which is enough for this single-host flow. */
    private static final Map<String, String> COOKIES = new LinkedHashMap<>();

    @BeforeAll
    static void startKeycloak() throws Exception {
        chain = new TestTrustChain();
        Path realmFile = writeRealmImport(chain);
        // The test realm declares a java-keystore KeyProvider for card ISSUANCE. This container
        // issues nothing, but the provider is loaded at startup: without the file, reading the
        // realm's keys would fail.
        Path keystoreFile = chain.writeCardIssuerKeystore("card-issuer", "changeit");

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
            // mode 0644: the temporary file is created 0600 by root, while the container runs as
            // "keycloak" (uid 1000) and must be able to read it at import.
            .withCopyFileToContainer(MountableFile.forHostPath(realmFile.toString(), 0644),
                "/opt/keycloak/data/import/realm-oid4vp-test.json")
            .withCopyFileToContainer(MountableFile.forHostPath(keystoreFile.toString(), 0644),
                "/opt/keycloak/data/oid4vp-test/card-issuer.p12")
            .withCommand("start-dev", "--import-realm")
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
            // getLogs() reads synchronously through the docker API; the asynchronous consumer can
            // lag behind the last lines, a 500 at the end of a test for instance.
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

    @Test
    void walletLoginHappyPathCreatesUserAndIssuesToken() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        // Keycloak 26 refuses "unmanaged" attributes by default, so the ENABLED policy is set for
        // the broker's oid4vp.* attributes to be persisted onto the created user.
        enableUnmanagedAttributes(browser);
        COOKIES.clear();

        // 1) The browser starts an authorization code flow on test-app with kc_idp_hint=oid4vp and
        //    follows through to the QR page rendered by performLogin.
        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=e2e-state"
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> qrPage = follow(browser, authUrl, null);
        assertEquals(200, qrPage.statusCode(), "expected the QR page (200), body=" + snippet(qrPage.body()));
        String html = qrPage.body();

        // The QR code is rendered by the SERVER. Against a real Keycloak, this is what proves the
        // runtime's ZXing classes are visible from the providers' classloader.
        //
        // The substring ties the data URI to OUR element rather than to "data:image/png;base64,"
        // alone: an inlined favicon from Keycloak's base theme carries that form too and would pass
        // the assertion without our feature doing anything.
        assertTrue(html.contains("<img id=\"oid4vp-qr-img\" src=\"data:image/png;base64,"),
            "the login page must carry the QR as an inlined PNG on OUR element, body=" + snippet(html));
        assertTrue(html.contains("oid4vp-wallet-link"),
            "the deep link must stay: on the same device the phone is both browser and wallet, "
                + "so there is nothing to scan");
        assertFalse(html.contains("window.QRCode"),
            "the dead JavaScript guard must be gone");

        // What only the server knows, and what the page could not say before.
        assertTrue(html.contains("This site is asking your wallet for the information below"),
            "the default purpose must be RESOLVED from the bundle, not rendered as a literal "
                + "${oid4vpDefaultPurpose}: that is the whole point of advancedMsg, and it has "
                + "never been observed for a template served from a provider JAR, body="
                + snippet(html));
        // This test's DCQL asks for given_name and age_over_18, and for nothing else. Asserting
        // both what is named and what is not is what proves the list is derived from the request
        // rather than written somewhere: a hardcoded list would pass the first half alone.
        assertTrue(html.contains("first name") && html.contains("whether you are over 18"),
            "the page must name the claims this DCQL asks for, labelled from the bundle, body="
                + snippet(html));
        assertFalse(html.contains("date of birth"),
            "a claim this request does not ask for must not appear: the list is read from the DCQL "
                + "being sent, not from a list somebody maintains, body=" + snippet(html));
        // The requested data is the page's most consequential content, and as plain prose it read
        // as an aside. It now sits in its own panel — and the panel has to CONTAIN its heading,
        // not merely follow it, or the list is framed while its own label is left outside. Index
        // order is what distinguishes the two, so it is what is asserted.
        assertTrue(html.contains("<div id=\"oid4vp-requested\">"),
            "the requested data must sit in its own panel, body=" + snippet(html));
        assertTrue(html.indexOf("oid4vp-requested") < html.indexOf("oid4vp-shared-intro"),
            "the panel must contain its heading, not follow it, body=" + snippet(html));
        // The heading names the list; the visual grouping alone does not say so out loud.
        assertTrue(html.contains("aria-labelledby=\"oid4vp-shared-intro\""),
            "the list must be labelled by its heading for a screen reader, body=" + snippet(html));

        assertTrue(html.contains("data-ttl-seconds=\"120\""),
            "the countdown needs the TTL the transaction was created with, body=" + snippet(html));

        assertTrue(html.contains("id=\"oid4vp-link-hint\""),
            "a deep link that leads nowhere fails silently on a desktop; the page must be able to "
                + "say so, body=" + snippet(html));
        assertFalse(html.contains("QR code to scan with your wallet"),
            "the alt text must offer an action rather than announce an unusable image, body="
                + snippet(html));
        assertTrue(html.indexOf("oid4vp-wallet-link") < html.indexOf("oid4vp-qr-img"),
            "the link must come before the code in the markup: nobody scans a code with the device "
                + "showing it, and a screen reader should meet the actionable path first. The "
                + "stylesheet, not the markup, decides what a wide screen shows first, body="
                + snippet(html));

        assertFalse(html.contains("\"Presentation was rejected.\"")
                || html.contains("\"The login request expired.\""),
            "no user-visible string may live in the script: it cannot be translated there, body="
                + snippet(html));
        assertTrue(html.contains("visibilitychange"),
            "on the same-device path the browser is backgrounded while the holder is in the "
                + "wallet; polling must resume the moment it returns, body=" + snippet(html));

        String statusUrl = extract(html, "var statusUrl = \"([^\"]+)\";");
        String completeUrl = extract(html, "var completeUrl = \"([^\"]+)\";");
        String tx = extract(statusUrl, "/status/([A-Za-z0-9_-]+)");
        String endpointBase = statusUrl.substring(0, statusUrl.indexOf("/status/"));

        // 2) The wallet, on the same TestTrustChain, fetches the Request Object, answers it and
        //    posts vp_token plus state as direct_post. The credential carries a persistent "sub",
        //    as a real PID does, and that is what founds the federated identity.
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", SUBJECT, "email", EMAIL, "given_name", GIVEN_NAME,
                "family_name", FAMILY_NAME, "age_over_18", true));

        HttpResponse<String> ro = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/request/" + tx))
                .header("Accept", "application/oauth-authz-req+jwt").GET());
        assertEquals(200, ro.statusCode(), "Request Object attendu (200)");
        String requestObject = ro.body();

        String vpToken = wallet.respondTo(requestObject, SimulatedWallet.Tamper.NONE);
        assertNotNull(vpToken, "le wallet doit produire un vp_token en Tamper.NONE");

        String responseForm = "response=" + enc(wallet.sealedResponse(vpToken, "A256GCM"));
        HttpResponse<String> posted = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/response/" + tx))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(responseForm)));
        assertEquals(200, posted.statusCode(), "expected direct_post (200), body=" + snippet(posted.body()));

        // 3) The browser polls until "completed".
        assertEquals("completed", pollUntilTerminal(browser, statusUrl), "the transaction must complete");

        // 4) Le navigateur suit complete/{tx} : reprise du flow -> redirection vers redirect_uri?code=...
        HttpResponse<String> completed = follow(browser, completeUrl, REDIRECT_URI);
        assertTrue(completed.statusCode() >= 300 && completed.statusCode() < 400,
            "complete doit rediriger vers le client, statut=" + completed.statusCode()
                + " corps=" + snippet(completed.body()));
        String location = completed.headers().firstValue("location").orElseThrow();
        assertTrue(location.startsWith(REDIRECT_URI), "redirection client attendue, location=" + location);
        String code = extract(location, "[?&]code=([^&]+)");

        // 5) Exchange the code at the token endpoint, then assert on what was issued.
        JsonNode token = formPost(browser, baseUrl + "/realms/" + REALM + "/protocol/openid-connect/token",
            "grant_type=authorization_code"
                + "&code=" + enc(code)
                + "&redirect_uri=" + enc(REDIRECT_URI)
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + enc(CLIENT_SECRET), null);
        assertTrue(token.hasNonNull("access_token"), "expected an access_token, response=" + token);
        assertTrue(token.hasNonNull("id_token"), "expected an id_token, response=" + token);

        // 5b) The DECODED ID token carries the OIDC4IDA verified_claims structure, produced by
        //     VerifiedClaimsMapper from the session notes the identity provider set. This proves
        //     the whole session note -> mapper -> token bridge against a real Keycloak.
        JsonNode idToken = decodeJwtPayload(token.get("id_token").asText());
        JsonNode verifiedClaims = idToken.get("verified_claims");
        assertNotNull(verifiedClaims, "verified_claims attendu dans l'ID token, payload=" + snippet(idToken.toString()));

        JsonNode verification = verifiedClaims.get("verification");
        assertNotNull(verification, "verified_claims.verification attendu, verified_claims=" + verifiedClaims);
        assertEquals("eidas", verification.path("trust_framework").asText(),
            "trust_framework doit venir de la config du mapper, verification=" + verification);

        JsonNode evidence = verification.get("evidence");
        assertNotNull(evidence, "expected verified_claims.verification.evidence, verification=" + verification);
        assertTrue(evidence.isArray() && evidence.size() >= 1, "evidence must be a non-empty array, evidence=" + evidence);
        JsonNode ev0 = evidence.get(0);
        assertEquals(VCT, ev0.path("vct").asText(), "evidence[0].vct must reflect the presented VC, evidence[0]=" + ev0);
        assertTrue(ev0.hasNonNull("issuer"), "expected evidence[0].issuer, evidence[0]=" + ev0);
        assertTrue(ev0.hasNonNull("trust_anchor"), "expected evidence[0].trust_anchor, evidence[0]=" + ev0);

        assertEquals(GIVEN_NAME, verifiedClaims.path("claims").path("given_name").asText(),
            "verified_claims.claims must carry the VC's verified claims, verified_claims=" + verifiedClaims);

        // ... and ONLY where the mapper is configured to emit it. The mapper is declared for all
        // four token types, and the *.token.claim switches bound the reach. The realm sets
        // access.token.claim=false, so the same session at the same instant must NOT carry
        // verified_claims in the access token.
        JsonNode accessToken = decodeJwtPayload(token.get("access_token").asText());
        assertNull(accessToken.get("verified_claims"),
            "access.token.claim=false must be honoured: no verified_claims in the access token, "
                + "payload=" + snippet(accessToken.toString()));

        // 6) Admin check: a user was created, with the profile and the oid4vp.given_name attribute.
        JsonNode adminToken = formPost(browser, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin", null);
        String bearer = adminToken.get("access_token").asText();

        HttpResponse<String> usersResp = exchange(browser,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/users?email=" + enc(EMAIL) + "&exact=true"))
                .header("Authorization", "Bearer " + bearer).GET());
        assertEquals(200, usersResp.statusCode(), "expected the admin user listing (200)");
        JsonNode users = MAPPER.readTree(usersResp.body());
        assertEquals(1, users.size(), "exactly one user created on the fly, response=" + usersResp.body());

        JsonNode user = users.get(0);
        assertEquals(EMAIL, user.get("email").asText());
        assertEquals(GIVEN_NAME, user.get("firstName").asText());
        assertEquals(FAMILY_NAME, user.get("lastName").asText());

        JsonNode attrs = user.get("attributes");
        assertNotNull(attrs, "expected user attributes, from the BrokeredIdentityContext");
        assertEquals(GIVEN_NAME, attrs.get("oid4vp.given_name").get(0).asText(),
            "the oid4vp.given_name attribute must be set on the created user");
        assertEquals(VCT, attrs.get("oid4vp.vct").get(0).asText());
    }

    /**
     * Changing the page language must return OUR page, in the chosen language.
     *
     * <p><b>What broke, and why nothing caught it.</b> Keycloak builds the switcher's links from the
     * current page's URL plus {@code kc_locale}. Ours is rendered by {@code performLogin} at
     * {@code /broker/{alias}/login}, which demands a single-use {@code session_code} the switcher
     * does not carry, so following the link answered 400. Every earlier test asserted on the markup
     * and never followed a link, and a browser set to French got a French page through
     * {@code Accept-Language} — so the defect only showed on a click.</p>
     *
     * <p><b>What this test does and does not cover.</b> The repointing itself happens in the browser:
     * the template rewrites each option's URL because Keycloak's switcher markup is out of our
     * reach. This client speaks HTTP and runs no script, so it performs that same rewrite by hand —
     * take the endpoint the page advertises, keep the query string Keycloak built, replace the path —
     * and then follows the result exactly as a browser would. That covers the server half end to end:
     * the endpoint exists, writes the locale, restarts the flow, and lands back on our page in the
     * new language. It does NOT execute the page's JavaScript, so the assertions below additionally
     * pin the script's presence and its selectors; without them the two halves could drift apart
     * silently, which is the failure mode this whole test exists to prevent.</p>
     *
     * <p>Asserting 200 alone would be worthless: restarting the flow reaches Keycloak's own login
     * form with a 200 too, and that is precisely one of the wrong destinations measured while
     * diagnosing this. The assertions therefore name our own element and our own French wording.</p>
     */
    @Test
    void languageSwitchReturnsOurPageInTheChosenLanguage() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=locale-state"
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> page = follow(browser, authUrl, null);
        assertEquals(200, page.statusCode(), "expected the login page (200), body=" + snippet(page.body()));
        String html = page.body();

        // The starting point must be English, or "it came back in French" would prove nothing.
        assertTrue(html.contains("This site is asking your wallet"),
            "the page must start in English for the switch to be observable, body=" + snippet(html));

        // The realm declares two locales, so Keycloak must have rendered a switcher at all. Without
        // this the test would pass vacuously the day internationalisation stops being imported.
        String optionUrl = firstMatch(html, "(?:value|href)=\"([^\"]*kc_locale=fr[^\"]*)\"");
        assertNotNull(optionUrl, "Keycloak must render a language option for fr, body=" + snippet(html));

        // The page must advertise where a language change has to go, and carry the script that
        // performs the rewrite for a real browser.
        String endpoint = firstMatch(html, "var endpoint = \"([^\"]+)\";");
        assertNotNull(endpoint, "the page must advertise the locale endpoint, body=" + snippet(html));
        assertTrue(html.contains("#login-select-toggle option[value]"),
            "the script must repoint the keycloak.v2 select, body=" + snippet(html));
        assertTrue(html.contains("#kc-locale a[href], #language-switch1 a[href]"),
            "the script must repoint the base theme's anchors, body=" + snippet(html));

        // Exactly what the script does: keep Keycloak's query string, replace the path.
        URI raw = URI.create(baseUrl).resolve(unescapeHtml(optionUrl));
        URI switchUrl = URI.create(URI.create(baseUrl).resolve(endpoint).toString() + "?" + raw.getRawQuery());

        HttpResponse<String> switched = follow(browser, switchUrl.toString(), null);
        assertEquals(200, switched.statusCode(),
            "the language switch must land on a page, not an error, body=" + snippet(switched.body()));
        String fr = switched.body();

        assertTrue(fr.contains("oid4vp-qr-img"),
            "the switch must return OUR page, not Keycloak's login form, body=" + snippet(fr));
        assertTrue(fr.contains("Ce site demande"),
            "our page must come back in French, body=" + snippet(fr));
    }

    /**
     * The locale endpoint must degrade, never break.
     *
     * <p>Two shapes reach it that the happy path does not. <b>Missing routing parameters:</b>
     * anyone can request the bare URL, and it must not answer 500 — which is exactly what it did
     * in production on 2026-08-26, because JAX-RS requires
     * {@code UriBuilder.replaceQueryParam} to reject a null value and the restart URL was built
     * from the query parameters unchecked. <b>Missing {@code client_data} alone:</b> this one is
     * not hypothetical and not malformed. {@code FreeMarkerLoginFormsProvider.prepareBaseUriBuilder}
     * omits {@code client_data} while the authentication session is logging out, so a switcher
     * link rendered in that state carries {@code client_id} and {@code tab_id} but no
     * {@code client_data} — a browser reaches this shape on its own, and it must still switch the
     * language.</p>
     */
    @Test
    void localeEndpointDegradesInsteadOfBreaking() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=degrade-state"
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> page = follow(browser, authUrl, null);
        assertEquals(200, page.statusCode(), "expected the login page (200), body=" + snippet(page.body()));
        String html = page.body();

        String endpoint = firstMatch(html, "var endpoint = \"([^\"]+)\";");
        assertNotNull(endpoint, "the page must advertise the locale endpoint, body=" + snippet(html));
        String endpointUrl = URI.create(baseUrl).resolve(endpoint).toString();

        String optionUrl = firstMatch(html, "(?:value|href)=\"([^\"]*kc_locale=fr[^\"]*)\"");
        assertNotNull(optionUrl, "Keycloak must render a language option for fr, body=" + snippet(html));
        String query = URI.create(baseUrl).resolve(unescapeHtml(optionUrl)).getRawQuery();
        String clientIdParam = firstMatch(query, "(?:^|&)(client_id=[^&]*)");
        String tabIdParam = firstMatch(query, "(?:^|&)(tab_id=[^&]*)");
        assertNotNull(clientIdParam, "Keycloak's switcher URL must carry client_id, query=" + query);
        assertNotNull(tabIdParam, "Keycloak's switcher URL must carry tab_id, query=" + query);

        // 1) No routing parameters at all. A refusal is correct; a 500 is not, and neither is a
        //    silent cookie write, which would record a language nothing is shown in.
        HttpResponse<String> bare = follow(browser, endpointUrl + "?kc_locale=fr", null);
        assertEquals(400, bare.statusCode(),
            "the bare endpoint must refuse cleanly, not throw, body=" + snippet(bare.body()));

        // 2) client_id and tab_id but no client_data — the shape Keycloak itself renders while a
        //    session is logging out. This must still switch the language.
        String noClientData = endpointUrl + "?kc_locale=fr&" + clientIdParam + "&" + tabIdParam;
        HttpResponse<String> switched = follow(browser, noClientData, null);
        assertEquals(200, switched.statusCode(),
            "a switcher link without client_data must still work, body=" + snippet(switched.body()));
        assertTrue(switched.body().contains("oid4vp-qr-img"),
            "it must return OUR page, body=" + snippet(switched.body()));
        assertTrue(switched.body().contains("Ce site demande"),
            "it must come back in French, body=" + snippet(switched.body()));
    }

    /**
     * The administration API must refuse an incoherent provider configuration, with a message.
     *
     * <p><b>This is the only test that proves the wiring.</b> The rules live in
     * {@code Oid4vpIdentityProviderConfig} and their unit tests instantiate that class directly, so
     * they would stay green even if {@code createConfig()} returned a bare
     * {@code IdentityProviderModel} and Keycloak never called any of them. Only a real server,
     * asked to save a real configuration, shows whether {@code validate} is on the path at all.</p>
     *
     * <p>It asserts the message too, not just the status. A 400 alone is what Keycloak answers for
     * a malformed request of any kind; what has to reach the administrator is the sentence naming
     * the field to fill.</p>
     *
     * <p>It lives in this class to share its container rather than pay another minute of startup
     * for one exchange. It creates nothing that survives: the provider is refused, which is the
     * point.</p>
     */
    @Test
    void theAdminApiRefusesAProviderMissingWhatItCannotWorkWithout() throws Exception {
        HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        JsonNode token = formPost(http, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin", null);
        String bearer = token.get("access_token").asText();

        // Everything the provider needs except the trust anchors, so the refusal can only come from
        // the rule under test and not from a generally malformed request.
        String body = """
            {"alias":"oid4vp-incomplete","providerId":"oid4vp","enabled":true,
             "config":{"signingKeyPem":"x","signingCertPem":"x","dcqlQueryJson":"{}"}}""";

        HttpResponse<String> created = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM + "/identity-provider/instances"))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));

        assertEquals(400, created.statusCode(),
            "saving a provider that cannot work must be refused, not stored; body="
                + snippet(created.body()));
        assertTrue(created.body().contains("Trust Anchors (PEM)"),
            "the refusal must name the field to fill, as the form labels it; body="
                + snippet(created.body()));
    }

    /**
     * The same flow as the happy path, but the wallet answers with a tampered {@code nonce}: the
     * KB-JWT binds the presentation to a nonce other than the one the Request Object issued. The
     * presentation is otherwise perfectly valid, so only the verification engine — not a shallow
     * shape check — can reject it.
     *
     * <p>It proves the transaction reaches {@code failed} and never {@code completed}, that
     * {@code complete/{tx}} yields no authorization code, and that NO user is created in the real
     * realm.</p>
     */
    @Test
    void walletLoginWrongNonceIsRejectedAndCreatesNoUser() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        String tamperedEmail = "eve-tampered@example.org";

        // 1) The same flow start as the happy path.
        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=e2e-state-tampered"
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> qrPage = follow(browser, authUrl, null);
        assertEquals(200, qrPage.statusCode(), "page QR attendue (200), corps=" + snippet(qrPage.body()));
        String html = qrPage.body();

        String statusUrl = extract(html, "var statusUrl = \"([^\"]+)\";");
        String completeUrl = extract(html, "var completeUrl = \"([^\"]+)\";");
        String tx = extract(statusUrl, "/status/([A-Za-z0-9_-]+)");
        String endpointBase = statusUrl.substring(0, statusUrl.indexOf("/status/"));

        // 2) The wallet fetches the real Request Object but answers with a tampered nonce. The
        //    presentation itself is valid and correctly signed; only the KB-JWT's link to the
        //    challenge nonce is wrong, which server-side cryptographic verification must catch.
        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("email", tamperedEmail, "given_name", "Eve", "family_name", "Tampered", "age_over_18", true));

        HttpResponse<String> ro = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/request/" + tx))
                .header("Accept", "application/oauth-authz-req+jwt").GET());
        assertEquals(200, ro.statusCode(), "Request Object attendu (200)");
        String requestObject = ro.body();

        String vpToken = wallet.respondTo(requestObject, SimulatedWallet.Tamper.WRONG_NONCE);
        assertNotNull(vpToken, "the wallet must produce a vp_token even when tampering");

        // A128GCM here (rather than A256GCM used elsewhere in this file): both advertised enc
        // values must be exercised end to end, not only the reference wallet's preference.
        String responseForm = "response=" + enc(wallet.sealedResponse(vpToken, "A128GCM"));
        HttpResponse<String> posted = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/response/" + tx))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(responseForm)));
        assertEquals(200, posted.statusCode(), "expected direct_post (200) even on asynchronous "
            + "failure, body=" + snippet(posted.body()));

        // 3) Polling must reach the terminal state "failed", never "completed".
        String terminalStatus = pollUntilTerminal(browser, statusUrl);
        assertEquals("failed", terminalStatus,
            "a vp_token with a forged nonce must be rejected by the verification engine");

        // 4) complete/{tx} must never yield an authorization code nor finish the login.
        // follow(..., REDIRECT_URI) returns a Location ONLY if a redirect reached REDIRECT_URI, the
        // sole path by which a code would be delivered; any other outcome has no Location here. If
        // one exists anyway, it is also checked to carry no "code=" .
        HttpResponse<String> completed = follow(browser, completeUrl, REDIRECT_URI);
        String location = completed.headers().firstValue("location").orElse(null);
        assertTrue(location == null || !location.contains("code="),
            "no authorization code may be issued for a forged presentation, status="
                + completed.statusCode() + " location=" + location + " body=" + snippet(completed.body()));

        // 5) The decisive admin check: ZERO users created for the email the malicious wallet
        //    presented. A forged presentation cannot create an identity.
        JsonNode adminToken = formPost(browser, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin", null);
        String bearer = adminToken.get("access_token").asText();

        HttpResponse<String> usersResp = exchange(browser,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/users?email=" + enc(tamperedEmail) + "&exact=true"))
                .header("Authorization", "Bearer " + bearer).GET());
        assertEquals(200, usersResp.statusCode(), "expected the admin user listing (200)");
        JsonNode users = MAPPER.readTree(usersResp.body());
        assertEquals(0, users.size(),
            "no user may be created for a presentation with a forged nonce, response="
                + usersResp.body());
    }

    /**
     * Regression pin for the hard switch to {@code direct_post.jwt}: every clear-text-refusal
     * test elsewhere in this codebase calls {@code PresentationEngine.processEncryptedWalletResponse}
     * directly, never through a real HTTP POST. That leaves a real gap — a regression that
     * restored a {@code @FormParam("vp_token")} on {@code Oid4vpEndpoints.response} and routed it
     * to the clear-text {@code processWalletResponse} would pass all engine-level unit tests
     * (they never touch the endpoint), yet would silently defeat the whole point of this branch:
     * accepting a clear-text response is exactly the HAIP violation the EUDI reference wallet
     * refused us for.
     *
     * <p>Builds a REAL, valid {@code vp_token} the same way the happy path does (so a would-be
     * regression that routes it through has every chance to succeed), but POSTS it as plain
     * {@code vp_token}/{@code state} form fields — the pre-encryption shape — instead of the
     * sealed {@code response} field the current endpoint actually reads. Today's endpoint ignores
     * both unrecognized fields, so the transaction fails on the resulting undecryptable (absent)
     * body; a regression reintroducing clear-text routing would instead complete it.</p>
     */
    @Test
    void aClearTextVpTokenPostedToResponseIsRejectedNotProcessed() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=e2e-state-cleartext"
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> qrPage = follow(browser, authUrl, null);
        assertEquals(200, qrPage.statusCode(), "page QR attendue (200), corps=" + snippet(qrPage.body()));
        String html = qrPage.body();

        String statusUrl = extract(html, "var statusUrl = \"([^\"]+)\";");
        String tx = extract(statusUrl, "/status/([A-Za-z0-9_-]+)");
        String endpointBase = statusUrl.substring(0, statusUrl.indexOf("/status/"));

        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain),
            Map.of("sub", "PID-CLEARTEXT-0003", "email", "cleartext@example.org",
                "given_name", "Clear", "family_name", "Text", "age_over_18", true));

        HttpResponse<String> ro = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/request/" + tx))
                .header("Accept", "application/oauth-authz-req+jwt").GET());
        assertEquals(200, ro.statusCode(), "Request Object attendu (200)");
        String requestObject = ro.body();

        // A real, verifiable vp_token: if a regression routed this through the clear-text path,
        // it would have every chance to succeed and COMPLETE the transaction.
        String vpToken = wallet.respondTo(requestObject, SimulatedWallet.Tamper.NONE);
        assertNotNull(vpToken, "le wallet doit produire un vp_token en Tamper.NONE");
        String state = decodeJwtPayload(requestObject).get("state").asText();

        // Posted as plain vp_token/state form fields — NOT the sealed `response` field the
        // hard-switched endpoint actually reads.
        String responseForm = "vp_token=" + enc(vpToken) + "&state=" + enc(state);
        HttpResponse<String> posted = exchange(browser,
            HttpRequest.newBuilder(URI.create(endpointBase + "/response/" + tx))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(responseForm)));
        assertEquals(200, posted.statusCode(), "expected direct_post (200) even on failure, body="
            + snippet(posted.body()));

        String terminalStatus = pollUntilTerminal(browser, statusUrl);
        assertEquals("failed", terminalStatus,
            "a clear-text vp_token/state POST must never complete a transaction: the hard switch "
                + "to direct_post.jwt must be enforced at the HTTP layer, not merely by unit tests "
                + "that call the engine directly");
    }

    /**
     * The identity is DURABLE. The same subject signs in TWICE, with two distinct presentations —
     * a fresh wallet, so a new holder key, a new credential, a new nonce and a new browser session
     * — from the SAME trust anchor and carrying the SAME {@code sub}.
     *
     * <p>It proves each login yields an authorization code, that only ONE user exists for that
     * email afterwards, and that the Keycloak {@code id} is IDENTICAL before and after: the same
     * account is found through the {@code issuer:sub} federated identity, not recreated.</p>
     */
    @Test
    void sameSubjectLogsBackIntoTheSameAccount() throws Exception {
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        COOKIES.clear();
        enableUnmanagedAttributes(browser);

        Map<String, Object> claims = Map.of(
            "sub", RELOGIN_SUBJECT, "email", RELOGIN_EMAIL,
            "given_name", "Rose", "family_name", "Relogin", "age_over_18", true);

        // First login: the account is created on the fly.
        LoginAttempt first = runWalletLogin(browser, "e2e-state-relogin-1", claims);
        assertEquals("completed", first.terminalStatus(), "the first presentation must verify");
        assertNotNull(first.code(), "the first login must produce an authorization code, location="
            + first.location());

        String bearer = adminBearer(browser);
        JsonNode usersAfterFirst = usersByEmail(browser, bearer, RELOGIN_EMAIL);
        assertEquals(1, usersAfterFirst.size(),
            "one user created at the first login, response=" + usersAfterFirst);
        String userIdAfterFirst = usersAfterFirst.get(0).get("id").asText();

        // Second login: a FRESH wallet (another holder key, a re-issued credential), a fresh
        // presentation and nonce, a browser session started from nothing — only the subject is
        // shared.
        LoginAttempt second = runWalletLogin(browser, "e2e-state-relogin-2", claims);
        assertEquals("completed", second.terminalStatus(), "the second presentation must verify");
        assertNotNull(second.code(), "the second login must produce an authorization code, location="
            + second.location());

        bearer = adminBearer(browser);
        JsonNode usersAfterSecond = usersByEmail(browser, bearer, RELOGIN_EMAIL);
        assertEquals(1, usersAfterSecond.size(),
            "signing in again must NOT create a second account, response=" + usersAfterSecond);
        assertEquals(userIdAfterFirst, usersAfterSecond.get(0).get("id").asText(),
            "durable identity: signing in again must land on the SAME Keycloak account");
    }

    /**
     * A CRYPTOGRAPHICALLY VALID presentation with NO stable subject cannot sign anyone in. The
     * wallet issues {@code email} and {@code given_name} only, with no {@code sub}, while the
     * identity provider runs {@code subjectClaim=sub} and {@code subjectPolicy=REJECT}.
     *
     * <p>Clearly distinct from the {@code WRONG_NONCE} case: there the cryptography fails and the
     * transaction reaches {@code failed}. Here verification SUCCEEDS — the presentation is
     * authentic — and it is the identity layer that refuses, for want of a durable identifier to
     * anchor the account on. No authorization code, and ZERO users created.</p>
     */
    @Test
    void validPresentationWithoutStableSubjectIsRefused() throws Exception {
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        COOKIES.clear();
        enableUnmanagedAttributes(browser);

        // Claims deliberately without "sub"; everything else matches the happy path.
        Map<String, Object> claims = Map.of(
            "email", NO_SUBJECT_EMAIL, "given_name", "Sans", "family_name", "Sujet", "age_over_18", true);

        LoginAttempt attempt = runWalletLogin(browser, "e2e-state-no-subject", claims);

        // 1) The verifier really does accept the presentation: signature, trust chain and the
        //    KB-JWT's link to the nonce are all correct. The refusal that follows is therefore not
        //    a cryptographic failure in disguise.
        assertEquals("completed", attempt.terminalStatus(),
            "the presentation is valid: the verifier must complete it, the refusal comes from the "
                + "identity layer");

        // 2) But the login is refused: complete/{tx} delivers no authorization code.
        assertNull(attempt.code(),
            "no authorization code without a stable subject, location=" + attempt.location());

        // 3) And above all: no account is created on the strength of a guessed identifier.
        String bearer = adminBearer(browser);
        JsonNode users = usersByEmail(browser, bearer, NO_SUBJECT_EMAIL);
        assertEquals(0, users.size(),
            "no user may be created for a presentation with no stable subject, response=" + users);
    }

    /** The outcome of a complete wallet login attempt: the transaction's terminal status and the
     *  final Location of {@code complete/{tx}}, null if the flow never redirected to the client. */
    private record LoginAttempt(String terminalStatus, String location) {
        /** The authorization code the Location carries, or {@code null}. */
        String code() {
            if (location == null) {
                return null;
            }
            Matcher m = Pattern.compile("[?&]code=([^&]+)").matcher(location);
            return m.find() ? m.group(1) : null;
        }
    }

    /**
     * Plays the complete wallet login flow — auth code with kc_idp_hint, QR page, Request Object,
     * direct_post presentation, polling, complete/{tx} — with a FRESH wallet on this run's
     * {@link TestTrustChain} and the given claims. It starts from a clean browser session so a
     * second login repeats the whole journey instead of being short-circuited by SSO.
     */
    private static LoginAttempt runWalletLogin(HttpClient browser, String state, Map<String, Object> claims)
        throws Exception {
        COOKIES.clear();

        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + enc(REDIRECT_URI)
            + "&response_type=code&scope=openid&state=" + enc(state)
            + "&kc_idp_hint=oid4vp";
        HttpResponse<String> qrPage = follow(browser, authUrl, null);
        assertEquals(200, qrPage.statusCode(), "page QR attendue (200), corps=" + snippet(qrPage.body()));

        String html = qrPage.body();
        String statusUrl = extract(html, "var statusUrl = \"([^\"]+)\";");
        String completeUrl = extract(html, "var completeUrl = \"([^\"]+)\";");
        String tx = extract(statusUrl, "/status/([A-Za-z0-9_-]+)");
        String endpointBase = statusUrl.substring(0, statusUrl.indexOf("/status/"));

        SimulatedWallet wallet = new SimulatedWallet(new TestCredentialIssuer(chain), claims);

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
        // the sole path by which an authorization code would be delivered.
        HttpResponse<String> completed = follow(browser, completeUrl, REDIRECT_URI);
        return new LoginAttempt(terminalStatus, completed.headers().firstValue("location").orElse(null));
    }

    /** Les utilisateurs du realm de test ayant exactement cet email (via l'API d'administration). */
    private static JsonNode usersByEmail(HttpClient http, String bearer, String email) throws Exception {
        HttpResponse<String> usersResp = exchange(http,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM
                    + "/users?email=" + enc(email) + "&exact=true"))
                .header("Authorization", "Bearer " + bearer).GET());
        assertEquals(200, usersResp.statusCode(), "liste des users admin attendue (200), corps="
            + snippet(usersResp.body()));
        return MAPPER.readTree(usersResp.body());
    }

    /**
     * {@code verified_claims} is emitted ONLY for a session born of a genuinely verified
     * presentation. The mapper's fail-closed guard — no {@code oid4vp.vc.presentations} note means
     * nothing is emitted — is exercised here on a session that never saw a wallet: an ordinary
     * password user of the SAME realm, on the SAME {@code test-app} client that carries the
     * protocol mapper, by direct grant. The ID token is issued normally, but WITHOUT
     * {@code verified_claims}.
     */
    @Test
    void passwordLoginWithoutPresentationHasNoVerifiedClaims() throws Exception {
        COOKIES.clear();
        HttpClient browser = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

        String bearer = adminBearer(browser);
        String userJson = """
            {"username":"%s","email":"%s","enabled":true,"emailVerified":true,\
            "firstName":"Paul","lastName":"Passeword",\
            "credentials":[{"type":"password","value":"%s","temporary":false}]}"""
            .formatted(PWD_USERNAME, PWD_EMAIL, PWD_PASSWORD);
        HttpResponse<String> created = exchange(browser,
            HttpRequest.newBuilder(URI.create(baseUrl + "/admin/realms/" + REALM + "/users"))
                .header("Authorization", "Bearer " + bearer)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(userJson)));
        assertEquals(201, created.statusCode(),
            "expected the password user to be created (201), body=" + snippet(created.body()));

        // scope=openid : sans lui, le direct grant ne renvoie pas d'id_token.
        JsonNode token = formPost(browser, baseUrl + "/realms/" + REALM + "/protocol/openid-connect/token",
            "grant_type=password&scope=openid"
                + "&client_id=" + CLIENT_ID
                + "&client_secret=" + enc(CLIENT_SECRET)
                + "&username=" + enc(PWD_USERNAME)
                + "&password=" + enc(PWD_PASSWORD), null);
        assertTrue(token.hasNonNull("id_token"), "expected an id_token for the direct grant, response=" + token);

        JsonNode idToken = decodeJwtPayload(token.get("id_token").asText());
        assertEquals(PWD_EMAIL, idToken.path("email").asText(),
            "the ID token must be the password user's, payload=" + snippet(idToken.toString()));
        assertNull(idToken.get("verified_claims"),
            "no verified presentation in this session: the mapper must stay silent, payload="
                + snippet(idToken.toString()));
    }

    /** An admin access token (master realm, admin-cli) for checks through the administration API. */
    private static String adminBearer(HttpClient http) throws Exception {
        JsonNode adminToken = formPost(http, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin", null);
        return adminToken.get("access_token").asText();
    }

    private static void enableUnmanagedAttributes(HttpClient http) throws Exception {
        JsonNode adminToken = formPost(http, baseUrl + "/realms/master/protocol/openid-connect/token",
            "grant_type=password&client_id=admin-cli&username=admin&password=admin", null);
        String bearer = adminToken.get("access_token").asText();
        String profileUrl = baseUrl + "/admin/realms/" + REALM + "/users/profile";

        HttpResponse<String> get = exchange(http, HttpRequest.newBuilder(URI.create(profileUrl))
            .header("Authorization", "Bearer " + bearer).header("Accept", "application/json").GET());
        assertEquals(200, get.statusCode(), "GET users/profile: " + snippet(get.body()));

        ObjectNode profile = (ObjectNode) MAPPER.readTree(get.body());
        profile.put("unmanagedAttributePolicy", "ENABLED");

        HttpResponse<String> put = exchange(http, HttpRequest.newBuilder(URI.create(profileUrl))
            .header("Authorization", "Bearer " + bearer)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(MAPPER.writeValueAsString(profile))));
        assertEquals(200, put.statusCode(), "PUT users/profile: " + put.statusCode() + " " + snippet(put.body()));
    }

    /** Decodes a compact JWT's payload — the second, base64url segment — into JSON. */
    private static JsonNode decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length, "expected a compact JWT of 3 segments, got=" + parts.length);
        byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
        return MAPPER.readTree(new String(payload, StandardCharsets.UTF_8));
    }

    // ---- helpers HTTP ----------------------------------------------------------

    /**
     * Follows redirects by hand, keeping cookies, until a non-3xx response — returned as is — or a
     * redirect whose Location starts with {@code stopPrefix}, returned unfollowed so the caller can
     * read that Location.
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

    private static JsonNode formPost(HttpClient http, String url, String body, String bearer) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            b.header("Authorization", "Bearer " + bearer);
        }
        HttpResponse<String> r = exchange(http, b);
        assertEquals(200, r.statusCode(), "POST " + url + " -> " + r.statusCode() + " : " + snippet(r.body()));
        return MAPPER.readTree(r.body());
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

    // ---- construction du realm -------------------------------------------------

    /**
     * <b>This container does NOT enable issuance.</b> {@code ownVct} and
     * {@code ownCredentialConfigId} are substituted EMPTY, which is exactly what "issuance entirely
     * inert" means: {@code Oid4vpConfig.ownVct()} returns {@code null} and
     * {@code ReofferRule.shouldOffer} leaves immediately on {@code false}.
     *
     * <p>The template used to carry issuance values hard-coded, for EVERY test sharing it. This one
     * stayed green not through inertness but through failure: the re-offer rule said yes at every
     * login, the grant found no {@code account-holder} credential scope in THIS container, a WARN
     * came out, the offer was abandoned and the login went on to the client — which is what the
     * {@code code=} assertions here observed. The day someone added that scope to the template,
     * this would have started breaking for an unrelated-looking reason. Declaring issuance test by
     * test removes the hidden coupling without duplicating the template.</p>
     */
    private static Path writeRealmImport(TestTrustChain chain) throws Exception {
        String template;
        try (InputStream in = WalletLoginE2eIT.class.getResourceAsStream("/realm-oid4vp-test.json")) {
            template = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        String realm = template
            .replace("@@CLIENT_SECRET@@", CLIENT_SECRET)
            .replace("@@TRUST_ANCHORS_PEM@@", jsonValue(pemCert(chain.caCert)))
            .replace("@@OWN_ISSUER_ANCHORS_PEM@@", "")
            .replace("@@SIGNING_KEY_PEM@@", jsonValue(pemPkcs8(chain.issuerKeyPair.getPrivate().getEncoded())))
            .replace("@@SIGNING_CERT_PEM@@", jsonValue(pemCert(chain.issuerCert)))
            .replace("@@OWN_VCT@@", "")
            .replace("@@OWN_CREDENTIAL_CONFIG_ID@@", "")
            .replace("@@DCQL_QUERY_JSON@@", jsonValue(DCQL_QUERY_JSON));

        Path file = Files.createTempFile("realm-oid4vp-test", ".json");
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

    // ---- petits utilitaires ----------------------------------------------------

    private static String extract(String source, String regex) {
        Matcher m = Pattern.compile(regex).matcher(source);
        if (!m.find()) {
            fail("motif introuvable [" + regex + "] dans : " + snippet(source));
        }
        return m.group(1);
    }

    /** First capturing group of {@code regex} in {@code s}, or {@code null} when it does not match. */
    private static String firstMatch(String s, String regex) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(regex).matcher(s);
        return m.find() ? m.group(1) : null;
    }

    /** The few entities FreeMarker's HTML escaping puts into an attribute value. */
    private static String unescapeHtml(String s) {
        return s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'")
            .replace("&lt;", "<").replace("&gt;", ">");
    }

    private static String enc(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String snippet(String s) {
        if (s == null) {
            return "<null>";
        }
        return s.length() > 500 ? s.substring(0, 500) + "..." : s;
    }
}
