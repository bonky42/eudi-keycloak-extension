package org.keycloak.protocol.oid4vc.vp.login.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@code scripts/prepare-demo} directly. No container is needed: the script requires
 * only {@code openssl}, which the build image provides.
 *
 * <p>This test lives outside the {@code it} package on purpose. Surefire excludes
 * {@code **}{@code /it/**} and Failsafe only includes {@code **}{@code /it/*IT.java}, so a
 * {@code *Test} placed under {@code it} would be run by neither.</p>
 *
 * <p>It asserts the two properties that stay invisible until something breaks far away: the
 * rendered realm is valid JSON with real PEM folded into it, and the verifier certificate and the
 * demo issuer CA are two <em>different</em> keys. Collapsing them would still produce a working
 * demo, and a lasting misconception — that a verifier is its own trust anchor.</p>
 */
class PrepareDemoTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static Path repoRoot() {
        return Paths.get(System.getProperty("user.dir")).getParent();
    }

    /** Runs the script and returns its exit code; the combined output is attached on failure. */
    private static int run(Path outDir, String... extraArgs) throws IOException, InterruptedException {
        String[] base = {repoRoot().resolve("scripts/prepare-demo").toString(),
                         "--host", "localhost", "--out-dir", outDir.toString()};
        String[] argv = new String[base.length + extraArgs.length];
        System.arraycopy(base, 0, argv, 0, base.length);
        System.arraycopy(extraArgs, 0, argv, base.length, extraArgs.length);

        Process process = new ProcessBuilder(argv)
            .directory(repoRoot().toFile())
            .redirectErrorStream(true)
            .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(120, TimeUnit.SECONDS), "prepare-demo timed out; output=" + output);
        return process.exitValue();
    }

    @Test
    void rendersARealmCarryingBothKeyPairs() throws Exception {
        Path outDir = Files.createTempDirectory("prepare-demo");

        assertEquals(0, run(outDir), "prepare-demo should succeed on an empty output directory");

        for (String name : new String[]{"verifier-key.pem", "verifier-cert.pem",
                                        "issuer-ca-key.pem", "issuer-ca-cert.pem", "realm.json"}) {
            assertTrue(Files.isRegularFile(outDir.resolve(name)), "missing output: " + name);
        }

        JsonNode realm = MAPPER.readTree(outDir.resolve("realm.json").toFile());
        assertEquals("oid4vp-demo", realm.get("realm").asText());

        JsonNode idp = realm.get("identityProviders").get(0);
        assertEquals("oid4vp", idp.get("providerId").asText());
        JsonNode config = idp.get("config");

        // The PEM survived the fold into a JSON string value: still a PEM, still multi-line.
        for (String key : new String[]{"signingKeyPem", "signingCertPem", "trustAnchorsPem"}) {
            String pem = config.get(key).asText();
            assertTrue(pem.startsWith("-----BEGIN "), key + " is not PEM: " + pem);
            assertTrue(pem.contains("\n"), key + " lost its line breaks");
        }

        // Recognition-only: issuance must stay off.
        assertTrue(config.get("ownVct") == null || config.get("ownVct").asText().isEmpty(),
            "ownVct must stay empty in the demo realm");

        // The verifier certificate and the trust anchor are opposite roles, and must not be the
        // same certificate.
        assertNotEquals(config.get("signingCertPem").asText(), config.get("trustAnchorsPem").asText(),
            "the verifier certificate must not double as the issuer trust anchor");
    }

    @Test
    void refusesToOverwriteWithoutForce() throws Exception {
        Path outDir = Files.createTempDirectory("prepare-demo-force");
        assertEquals(0, run(outDir));
        String firstKey = Files.readString(outDir.resolve("verifier-key.pem"));

        assertNotEquals(0, run(outDir), "a second run without --force must fail");
        assertEquals(firstKey, Files.readString(outDir.resolve("verifier-key.pem")),
            "the refused run must leave the existing key untouched");

        assertEquals(0, run(outDir, "--force"), "--force must regenerate");
        assertNotEquals(firstKey, Files.readString(outDir.resolve("verifier-key.pem")),
            "--force must produce a new key");
    }
}
