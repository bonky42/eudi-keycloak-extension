package org.keycloak.protocol.oid4vc.vp.login.it;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves that the realm produced by {@code scripts/prepare-demo} actually works: it imports into a
 * real Keycloak 26.7.2 carrying the extension, and its login page renders a server-side QR.
 *
 * <p>The test drives the <em>real</em> script rather than generating equivalent PKI in Java. A
 * test that reimplements the script's intent in another language leaves the script itself
 * untested — and the PEM-into-JSON fold is exactly the kind of defect such a reimplementation
 * would miss.</p>
 */
class DemoRealmIT {

    private static final String REALM = "oid4vp-demo";
    private static final String CLIENT_ID = "demo-app";
    private static final String REDIRECT_URI = "http://localhost/demo/callback";

    private static GenericContainer<?> keycloak;
    private static String baseUrl;

    @BeforeAll
    static void startKeycloak() throws Exception {
        Path repoRoot = Paths.get(System.getProperty("user.dir")).getParent();
        Path outDir = Files.createTempDirectory("demo-realm-it");

        Process prepare = new ProcessBuilder(
                repoRoot.resolve("scripts/prepare-demo").toString(),
                "--host", "localhost", "--out-dir", outDir.toString())
            .directory(repoRoot.toFile())
            .redirectErrorStream(true)
            .start();
        String prepareOutput = new String(prepare.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(prepare.waitFor(120, TimeUnit.SECONDS), "prepare-demo timed out");
        assertEquals(0, prepare.exitValue(), "prepare-demo failed:\n" + prepareOutput);

        Path moduleDir = Paths.get(System.getProperty("user.dir"));
        Path loginJar = moduleDir.resolve("target/oid4vp-login-0.1.0-SNAPSHOT.jar");
        Path coreJar = moduleDir.resolve("../oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar").normalize();
        assertTrue(Files.isRegularFile(loginJar), "provider JAR missing (run via `verify`, not `test`): " + loginJar);
        assertTrue(Files.isRegularFile(coreJar), "provider JAR missing (run via `verify`, not `test`): " + coreJar);

        keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.7.2"))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCopyFileToContainer(MountableFile.forHostPath(coreJar.toString()),
                "/opt/keycloak/providers/oid4vp-core.jar")
            .withCopyFileToContainer(MountableFile.forHostPath(loginJar.toString()),
                "/opt/keycloak/providers/oid4vp-login.jar")
            // 0644: the rendered realm is created 0600 by root, and the container runs as uid 1000.
            .withCopyFileToContainer(
                MountableFile.forHostPath(outDir.resolve("realm.json").toString(), 0644),
                "/opt/keycloak/data/import/realm-oid4vp-demo.json")
            .withCommand("start-dev", "--import-realm")
            .waitingFor(Wait.forHttp("/realms/" + REALM).forPort(8080).forStatusCode(200)
                .withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();

        baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    @Test
    void theImportedRealmRendersAQrOnTheLoginPage() throws Exception {
        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
            + "&response_type=code&scope=openid&state=demo-state"
            + "&kc_idp_hint=oid4vp";

        HttpResponse<String> page = new HttpBrowser().get(authUrl);

        assertEquals(200, page.statusCode(), "expected the QR page; body=" + snippet(page.body()));
        assertTrue(page.body().contains("<img id=\"oid4vp-qr-img\" src=\"data:image/png;base64,"),
            "the login page carries no server-rendered QR; body=" + snippet(page.body()));
    }

    /**
     * The shipped realm must let a visitor reach the French page.
     *
     * <p>The repository ships a complete French bundle, and the demo realm did not enable
     * internationalisation — so the switcher never rendered and the translation could not be
     * chosen by anyone running the published demo. Asserting that the selector exists would not
     * catch that on its own: what matters is that following it arrives somewhere French, which is
     * the whole chain (the realm's locales, the endpoint, the cookie, the flow restart).</p>
     *
     * <p>Like the switcher itself, this performs in one step what the page's script does in the
     * browser: keep the query Keycloak built, replace the path with the endpoint the page
     * advertises.</p>
     */
    @Test
    void theImportedRealmCanBeReadInFrench() throws Exception {
        String authUrl = baseUrl + "/realms/" + REALM + "/protocol/openid-connect/auth"
            + "?client_id=" + CLIENT_ID
            + "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
            + "&response_type=code&scope=openid&state=demo-locale"
            + "&kc_idp_hint=oid4vp";

        HttpBrowser browser = new HttpBrowser();
        HttpResponse<String> page = browser.get(authUrl);
        assertEquals(200, page.statusCode(), "expected the login page; body=" + snippet(page.body()));
        String html = page.body();

        String option = group(html, "(?:value|href)=\"([^\"]*kc_locale=fr[^\"]*)\"");
        assertTrue(option != null,
            "the demo realm must offer French: internationalizationEnabled and supportedLocales "
                + "have to be in the imported realm, or the shipped bundle is unreachable; body="
                + snippet(html));
        String endpoint = group(html, "var endpoint = \"([^\"]+)\";");
        assertTrue(endpoint != null, "the page must advertise the locale endpoint; body=" + snippet(html));

        String query = URI.create(baseUrl).resolve(option.replace("&amp;", "&")).getRawQuery();
        HttpResponse<String> french = browser.get(endpoint + "?" + query);

        assertEquals(200, french.statusCode(), "the language switch must land on a page; body="
            + snippet(french.body()));
        assertTrue(french.body().contains("Ce site demande"),
            "the demo must be readable in French; body=" + snippet(french.body()));
    }

    private static String group(String s, String regex) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile(regex).matcher(s);
        return m.find() ? m.group(1) : null;
    }

    private static String snippet(String body) {
        return body == null ? "<null>" : body.substring(0, Math.min(600, body.length()));
    }
}
