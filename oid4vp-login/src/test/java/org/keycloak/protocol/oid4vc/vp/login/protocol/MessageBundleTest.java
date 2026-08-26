package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The login page's message bundles.
 *
 * <p>The languages must stay in step. A key added to one and forgotten in the other shows the raw
 * key to the holder — silently, and only in that language, which is the hardest kind of defect to
 * notice from the language you happen to speak.</p>
 */
class MessageBundleTest {

    private static final List<String> LOCALES = List.of("en", "fr");

    /** Keys the template and the script depend on. A rename here must break a test, not a page. */
    private static final Set<String> REQUIRED = Set.of(
        "oid4vpLoginTitle", "oid4vpDefaultPurpose", "oid4vpSharedIntro", "oid4vpScanInstructions",
        "oid4vpQrAlt", "oid4vpOpenWallet", "oid4vpLinkHint", "oid4vpWaiting", "oid4vpExpiresIn",
        "oid4vpExpired", "oid4vpRejected", "oid4vpConnectionLost", "oid4vpRetry");

    private static Properties bundle(String locale) throws Exception {
        String path = "theme-resources/messages/messages_" + locale + ".properties";
        try (InputStream in = MessageBundleTest.class.getClassLoader().getResourceAsStream(path)) {
            assertNotNull(in, "bundle not on the classpath: " + path + " — it must live under "
                + "theme-resources/messages/, because a bundle under theme/<name>/ loads when the "
                + "theme comes from a directory and NOT when it comes from a provider JAR, which "
                + "is how this extension ships");
            Properties properties = new Properties();
            properties.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            return properties;
        }
    }

    @Test
    void everyLanguageDefinesTheSameKeys() throws Exception {
        Set<String> en = new TreeSet<>(bundle("en").stringPropertyNames());
        Set<String> fr = new TreeSet<>(bundle("fr").stringPropertyNames());
        assertEquals(en, fr, "the bundles must define exactly the same keys: a key present in one "
            + "language only shows as its raw key to whoever reads the other");
    }

    @Test
    void everyKeyThePageDependsOnIsDefined() throws Exception {
        for (String locale : LOCALES) {
            Set<String> defined = bundle(locale).stringPropertyNames();
            for (String key : REQUIRED) {
                assertTrue(defined.contains(key), "missing " + key + " in " + locale);
            }
        }
    }

    @Test
    void noValueIsEmpty() throws Exception {
        for (String locale : LOCALES) {
            Properties properties = bundle(locale);
            for (String key : properties.stringPropertyNames()) {
                assertFalse(properties.getProperty(key).isBlank(),
                    "empty value for " + key + " in " + locale + ": the holder would see nothing "
                        + "where a sentence belongs, which reads as a broken page");
            }
        }
    }

    @Test
    void theCountdownSentenceKeepsItsPlaceholder() throws Exception {
        for (String locale : LOCALES) {
            assertTrue(bundle(locale).getProperty("oid4vpExpiresIn", "").contains("{0}"),
                "oid4vpExpiresIn in " + locale + " must keep {0}: the script substitutes the "
                    + "remaining time into it, and a translation that drops the placeholder "
                    + "silently shows a sentence with no number in it");
        }
    }

    @Test
    void everyClaimLabelIsTranslatedInBothLanguages() throws Exception {
        Properties en = bundle("en");
        long labels = en.stringPropertyNames().stream().filter(k -> k.startsWith("oid4vpClaim.")).count();
        assertTrue(labels > 0, "at least the claims of the shipped demo DCQL should have a label");
        // Covered by everyLanguageDefinesTheSameKeys as well; asserted here so a failure names the
        // claim labels rather than the whole bundle.
        Set<String> enLabels = new TreeSet<>(en.stringPropertyNames());
        enLabels.removeIf(k -> !k.startsWith("oid4vpClaim."));
        Set<String> frLabels = new TreeSet<>(bundle("fr").stringPropertyNames());
        frLabels.removeIf(k -> !k.startsWith("oid4vpClaim."));
        assertEquals(enLabels, frLabels, "a claim labelled in one language only falls back to its "
            + "technical name for the other, which is a worse experience than no label at all");
    }
}
