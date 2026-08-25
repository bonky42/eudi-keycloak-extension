package org.keycloak.protocol.oid4vc.vp.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * The ephemeral encryption key pair for one presentation transaction.
 *
 * <p>The HAIP profile requires the verifier to supply "ephemeral encryption public keys specific to
 * each Authorization Request". A realm key would be non-conforming, and one compromised key would
 * open every past response.
 *
 * <p>Stored as two opaque base64 strings rather than a JWK: the value is written to a store and
 * read back on a later request, and a re-parsed JWK adds a conversion on that path. The JWK is
 * built only when the request object is emitted.
 */
public final class ResponseEncryptionKey {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final int P256_COORDINATE_BYTES = 32;

    private final String kid;
    private final KeyPair keyPair;

    private ResponseEncryptionKey(String kid, KeyPair keyPair) {
        this.kid = kid;
        this.keyPair = keyPair;
    }

    public static ResponseEncryptionKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            byte[] kid = new byte[16];
            new SecureRandom().nextBytes(kid);
            return new ResponseEncryptionKey(B64URL_NOPAD.encodeToString(kid), generator.generateKeyPair());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate response encryption key", e);
        }
    }

    public static ResponseEncryptionKey restore(String kid, String privateKeyB64, String publicKeyB64) {
        try {
            KeyFactory factory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = factory.generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyB64)));
            PublicKey publicKey = factory.generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64)));
            return new ResponseEncryptionKey(kid, new KeyPair(publicKey, privateKey));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to restore response encryption key", e);
        }
    }

    public String kid() {
        return kid;
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    public String privateKeyB64() {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    public String publicKeyB64() {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /** The public key as a JWK, for {@code client_metadata.jwks}. */
    public ObjectNode publicJwk() {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ObjectNode jwk = MAPPER.createObjectNode();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("use", "enc");
        jwk.put("alg", "ECDH-ES");
        jwk.put("kid", kid);
        jwk.put("x", coordinate(publicKey.getW().getAffineX()));
        jwk.put("y", coordinate(publicKey.getW().getAffineY()));
        return jwk;
    }

    /**
     * A P-256 coordinate is exactly 32 bytes, left-padded with zeroes. {@code BigInteger#toByteArray}
     * gives neither guarantee: it prepends a sign byte for values with the high bit set, and drops
     * leading zeroes otherwise. Emitting that raw produces a 31- or 33-byte coordinate that some
     * peers reject.
     */
    private static String coordinate(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] fixed = new byte[P256_COORDINATE_BYTES];
        if (raw.length > P256_COORDINATE_BYTES) {
            System.arraycopy(raw, raw.length - P256_COORDINATE_BYTES, fixed, 0, P256_COORDINATE_BYTES);
        } else {
            System.arraycopy(raw, 0, fixed, P256_COORDINATE_BYTES - raw.length, raw.length);
        }
        return B64URL_NOPAD.encodeToString(fixed);
    }
}
