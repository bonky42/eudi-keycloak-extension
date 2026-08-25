package org.keycloak.protocol.oid4vc.vp.verifier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.protocol.oid4vc.vp.request.ResponseEncryptionKey;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestJwe;

import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The fixtures are produced by jwcrypto, a different JWE implementation.
 * That is deliberate: a JWE built by our own encryptor would only prove we agree with ourselves,
 * and the `apu`/`apv` key-agreement inputs are exactly where two "correct" implementations can
 * still fail to meet.
 */
class EncryptedResponseTest {

    private static CryptoProvider realCryptoProvider;

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(EncryptedResponseTest.class.getClassLoader());
        realCryptoProvider = CryptoIntegration.getProvider();
    }

    @AfterEach
    void restoreRealCryptoProvider() {
        // A test below swaps in a fake CryptoProvider via CryptoIntegration.setProvider (a
        // process-wide static); undo it unconditionally so later tests in this class (or run
        // after it in the same JVM) are never left decrypting against a crippled provider.
        // CryptoIntegration.init() alone does not do this: it is a no-op once already initialised.
        CryptoIntegration.setProvider(realCryptoProvider);
    }

    /**
     * {@link EncryptedResponse#algorithmProvider()} is resolved through {@link CryptoIntegration}
     * precisely so a FIPS crypto module can be swapped in — and such a module might not register
     * ECDH-ES. Previously a {@code null} there propagated silently into
     * {@code jwe.verifyAndDecodeJwe}, producing an NPE indistinguishable, from the operator's
     * seat, from an ordinary wallet-caused decryption failure (both surface as
     * {@code RESPONSE_DECRYPTION_FAILED}). Simulates that by swapping in a {@link CryptoProvider}
     * that answers {@code null} for ECDH-ES specifically (a JDK dynamic proxy delegating
     * everything else to the real provider — no need to hand-implement the whole interface).
     */
    @Test
    void algorithmProviderFailsWithAMessageNamingTheRealCauseWhenEcdhEsIsNotRegistered() {
        CryptoProvider withoutEcdhEs = (CryptoProvider) Proxy.newProxyInstance(
            CryptoProvider.class.getClassLoader(),
            new Class<?>[] {CryptoProvider.class},
            (proxy, method, args) -> {
                if ("getAlgorithmProvider".equals(method.getName())
                    && args != null && args.length == 2 && "ECDH-ES".equals(args[1])) {
                    return null;
                }
                return method.invoke(realCryptoProvider, args);
            });
        CryptoIntegration.setProvider(withoutEcdhEs);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
            EncryptedResponse::algorithmProvider);

        assertTrue(failure.getMessage().contains("ECDH-ES"),
            "the message must name the real cause (missing ECDH-ES provider), not a generic "
                + "decryption failure, message=" + failure.getMessage());
    }

    @Test
    void decryptsAForeignJweUnderA256Gcm() throws Exception {
        EncryptedResponse.WalletResponse response =
            EncryptedResponse.decrypt(resource("haip/foreign-jwe-a256gcm.txt"), fixtureKey());

        assertEquals("FIXTURE_STATE", response.state());
        assertTrue(response.vpToken().contains("PLACEHOLDER"));
    }

    @Test
    void decryptsAForeignJweUnderA128Gcm() throws Exception {
        EncryptedResponse.WalletResponse response =
            EncryptedResponse.decrypt(resource("haip/foreign-jwe-a128gcm.txt"), fixtureKey());

        assertEquals("FIXTURE_STATE", response.state());
    }

    /**
     * {@code apu}/{@code apv} are inputs to the ECDH-ES key derivation (OID4VP 1.0 §8.3). The other
     * two fixtures carry neither, so they cannot prove Keycloak's provider consumes them the way a
     * foreign implementation produces them. This test is the one that can.
     */
    @Test
    void decryptsAForeignJweCarryingApuAndApv() throws Exception {
        EncryptedResponse.WalletResponse response =
            EncryptedResponse.decrypt(resource("haip/foreign-jwe-a256gcm-apu-apv.txt"), fixtureKey());

        assertEquals("FIXTURE_STATE", response.state());
    }

    @Test
    void opensWhatTheSimulatedWalletSeals() throws Exception {
        ResponseEncryptionKey key = ResponseEncryptionKey.generate();
        String sealed = TestJwe.seal(key.publicJwk(), "A256GCM",
            "{\"vp_token\":{\"pid\":[\"abc\"]},\"state\":\"ST\"}");

        EncryptedResponse.WalletResponse response = EncryptedResponse.decrypt(sealed, key.privateKey());

        assertEquals("ST", response.state());
    }

    @Test
    void refusesAResponseSealedToAnotherKey() {
        PrivateKey stranger = ResponseEncryptionKey.generate().privateKey();

        VpVerificationException failure = assertThrows(VpVerificationException.class,
            () -> EncryptedResponse.decrypt(resource("haip/foreign-jwe-a256gcm.txt"), stranger));

        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED, failure.getCode());
    }

    @Test
    void refusesCiphertextAlteredByOneCharacter() throws Exception {
        String jwe = resource("haip/foreign-jwe-a256gcm.txt");
        String[] parts = jwe.split("\\.");
        // flip one character of the ciphertext segment; the AEAD tag must catch it
        char first = parts[3].charAt(0);
        parts[3] = (first == 'A' ? 'B' : 'A') + parts[3].substring(1);
        String tampered = String.join(".", parts);

        VpVerificationException failure = assertThrows(VpVerificationException.class,
            () -> EncryptedResponse.decrypt(tampered, fixtureKey()));

        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED, failure.getCode());
    }

    @Test
    void refusesSomethingThatIsNotAJwe() {
        VpVerificationException failure = assertThrows(VpVerificationException.class,
            () -> EncryptedResponse.decrypt("{\"vp_token\":{}}", fixtureKey()));

        assertEquals(VpErrorCode.RESPONSE_DECRYPTION_FAILED, failure.getCode());
    }

    private static PrivateKey fixtureKey() throws Exception {
        byte[] der = Base64.getDecoder().decode(resource("haip/foreign-private-key.b64").trim());
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static String resource(String path) {
        try (InputStream in = EncryptedResponseTest.class.getClassLoader().getResourceAsStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new IllegalStateException("missing test resource " + path, e);
        }
    }
}
