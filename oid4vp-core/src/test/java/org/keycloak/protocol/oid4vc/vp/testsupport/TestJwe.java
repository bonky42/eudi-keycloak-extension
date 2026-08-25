package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.AesGcmJWEEncryptionProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.AlgorithmParameters;
import java.security.spec.ECParameterSpec;
import java.util.Base64;

/** Seals a payload the way a HAIP wallet does: ECDH-ES to the verifier's ephemeral P-256 key. */
public final class TestJwe {

    private TestJwe() {
    }

    public static String seal(ObjectNode publicJwk, String enc, String plaintext) {
        try {
            JWEHeader header = new JWEHeader.JWEHeaderBuilder()
                .algorithm(JWEConstants.ECDH_ES)
                .encryptionAlgorithm(enc)
                .keyId(publicJwk.get("kid").asText())
                .build();
            JWE jwe = new JWE().header(header).content(plaintext.getBytes(StandardCharsets.UTF_8));
            jwe.getKeyStorage().setEncryptionKey(publicKeyOf(publicJwk));

            JWEAlgorithmProvider alg = CryptoIntegration.getProvider()
                .getAlgorithmProvider(JWEAlgorithmProvider.class, JWEConstants.ECDH_ES);
            return jwe.encodeJwe(alg, new AesGcmJWEEncryptionProvider(enc));
        } catch (Exception e) {
            throw new IllegalStateException("failed to seal test response", e);
        }
    }

    private static PublicKey publicKeyOf(ObjectNode jwk) throws Exception {
        Base64.Decoder b64 = Base64.getUrlDecoder();
        ECPoint point = new ECPoint(
            new BigInteger(1, b64.decode(jwk.get("x").asText())),
            new BigInteger(1, b64.decode(jwk.get("y").asText())));
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }
}
