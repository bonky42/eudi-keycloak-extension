package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;

/**
 * Forges a test KB-JWT ({@code typ: "kb+jwt"}), as a wallet answering a presentation request would.
 * ES256-signed by the holder's key.
 */
public final class KbJwtSigner {

    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private KbJwtSigner() {
    }

    /**
     * Construit un KB-JWT avec un {@code iat} courant et le {@code sd_hash}
     * correct de {@code presentationWithoutKb}.
     */
    public static String sign(KeyPair holder, String nonce, String aud, String presentationWithoutKb) {
        return sign(holder, nonce, aud, presentationWithoutKb, Instant.now().getEpochSecond());
    }

    /**
     * Like {@link #sign(KeyPair, String, String, String)}, with an imposed {@code iat} for the
     * freshness tests.
     */
    public static String sign(KeyPair holder, String nonce, String aud, String presentationWithoutKb, long iat) {
        return sign(holder, nonce, aud, iat, sdHashOf(presentationWithoutKb));
    }

    /**
     * Builds a KB-JWT with an explicit {@code sd_hash}, so it can be deliberately detached from
     * {@code presentationWithoutKb} for a negative test.
     */
    public static String signWithSdHash(KeyPair holder, String nonce, String aud, long iat, String sdHash) {
        return sign(holder, nonce, aud, iat, sdHash);
    }

    private static String sign(KeyPair holder, String nonce, String aud, long iat, String sdHash) {
        try {
            ObjectNode header = MAPPER.createObjectNode();
            header.put("alg", "ES256");
            header.put("typ", "kb+jwt");

            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("nonce", nonce);
            payload.put("aud", aud);
            payload.put("iat", iat);
            payload.put("sd_hash", sdHash);

            String headerB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(header));
            String payloadB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(payload));
            String signingInput = headerB64 + "." + payloadB64;

            Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            signature.initSign(holder.getPrivate());
            signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] sig = signature.sign();

            return signingInput + "." + B64URL_NOPAD.encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign test KB-JWT", e);
        }
    }

    /**
     * base64url (sans padding) de SHA-256(presentationWithoutKb en ASCII) — la
     * valeur attendue du claim {@code sd_hash}.
     */
    public static String sdHashOf(String presentationWithoutKb) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(presentationWithoutKb.getBytes(StandardCharsets.US_ASCII));
            return B64URL_NOPAD.encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
