package org.keycloak.protocol.oid4vc.vp.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;

/**
 * Opens the JWE a wallet posts under {@code response_mode=direct_post.jwt}, and does nothing else.
 *
 * <p>It knows nothing about presentations, DCQL or trust: it takes a compact JWE and returns the
 * {@code vp_token} and {@code state} that were sealed inside. Everything after that is the existing
 * pipeline, unchanged.
 */
public final class EncryptedResponse {

    private static final Logger LOG = Logger.getLogger(EncryptedResponse.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * The single source of truth for which JWE {@code enc} values this verifier both advertises
     * (via {@code encrypted_response_enc_values_supported} in
     * {@link org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder}) and accepts here
     * (see {@link #encryptionProvider(String)}). HAIP requires both {@code A128GCM} and
     * {@code A256GCM} to be advertised, and the wallet picks whichever it likes — so the two
     * lists must never be allowed to drift apart: advertising a value we then refuse would break
     * a compliant wallet that took us up on it.
     */
    public static final List<String> SUPPORTED_ENC_VALUES = List.of(JWEConstants.A128GCM, JWEConstants.A256GCM);

    /** @param vpToken the serialized JSON of the {@code vp_token} member, as the engine expects it */
    public record WalletResponse(String vpToken, String state, String error) {
    }

    private EncryptedResponse() {
    }

    public static WalletResponse decrypt(String compactJwe, PrivateKey key)
            throws VpVerificationException {
        try {
            JWE jwe = new JWE();
            jwe.getKeyStorage().setDecryptionKey(key);
            jwe.verifyAndDecodeJwe(compactJwe, algorithmProvider(), encryptionProvider(compactJwe));

            JsonNode body = MAPPER.readTree(new String(jwe.getContent(), StandardCharsets.UTF_8));
            JsonNode vpToken = body.get("vp_token");
            return new WalletResponse(
                vpToken == null ? null : MAPPER.writeValueAsString(vpToken),
                body.path("state").asText(null),
                body.path("error").asText(null));
        } catch (Exception e) {
            // The cause is never surfaced to the wallet or the browser, and the decrypted body is
            // never logged.
            throw new VpVerificationException(VpErrorCode.RESPONSE_DECRYPTION_FAILED,
                "wallet response could not be decrypted");
        }
    }

    /**
     * Package-private (rather than {@code private}) solely so {@code EncryptedResponseTest} can
     * call it directly and assert on the exception it throws when {@code CryptoIntegration}'s
     * provider does not register ECDH-ES — {@link #decrypt(String, PrivateKey)} wraps every
     * failure in a uniform {@link VpErrorCode#RESPONSE_DECRYPTION_FAILED}, which would otherwise
     * make that case indistinguishable, from the outside, from an ordinary wallet-caused failure.
     */
    static JWEAlgorithmProvider algorithmProvider() {
        // Resolved through CryptoIntegration rather than by naming BCEcdhEsAlgorithmProvider
        // directly: that class lives in keycloak-crypto-default, a module whose name says it is
        // interchangeable, and which has a FIPS counterpart — one that might not register ECDH-ES.
        CryptoProvider provider = CryptoIntegration.getProvider();
        JWEAlgorithmProvider algorithmProvider =
            provider.getAlgorithmProvider(JWEAlgorithmProvider.class, JWEConstants.ECDH_ES);
        if (algorithmProvider == null) {
            // Logged (not just thrown): decrypt() below swallows this into the same
            // RESPONSE_DECRYPTION_FAILED as every wallet-caused failure, on purpose (its cause is
            // never surfaced externally) — this ERROR line is the only place an operator can see
            // that the real cause is a missing server-side crypto registration, not the wallet.
            LOG.errorf("No ECDH-ES JWEAlgorithmProvider registered by the active CryptoProvider "
                    + "(%s); every direct_post.jwt response will fail to decrypt until this is fixed "
                    + "server-side (e.g. a FIPS crypto module not registering ECDH-ES)",
                provider.getClass().getName());
            throw new IllegalStateException(
                "ECDH-ES JWEAlgorithmProvider not available from the active CryptoProvider ("
                    + provider.getClass().getName() + ")");
        }
        return algorithmProvider;
    }

    /**
     * The {@code enc} must be read from the header before decrypting, because the wallet chooses it
     * and the profile obliges us to accept either.
     */
    private static JWEEncryptionProvider encryptionProvider(String compactJwe) throws Exception {
        String headerB64 = compactJwe.substring(0, compactJwe.indexOf('.'));
        JsonNode header = MAPPER.readTree(Base64.getUrlDecoder().decode(headerB64));
        String enc = header.path("enc").asText();
        if (!SUPPORTED_ENC_VALUES.contains(enc)) {
            throw new IllegalArgumentException("unsupported enc");
        }
        return new AesGcmJWEEncryptionProvider(enc);
    }
}
