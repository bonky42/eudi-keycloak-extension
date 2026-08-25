package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/** The JWK form of an EC P-256 public key, shared by simulated issuance (the credential's cnf) and
 *  the OID4VCI proof of possession (the jwk header). */
public final class EcJwk {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    private EcJwk() {
    }

    public static ObjectNode publicJwk(PublicKey key) {
        if (!(key instanceof ECPublicKey ecPublicKey)) {
            throw new IllegalArgumentException("key must be an EC public key");
        }
        ObjectNode jwk = MAPPER.createObjectNode();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", B64URL_NOPAD.encodeToString(toFixedLength(ecPublicKey.getW().getAffineX())));
        jwk.put("y", B64URL_NOPAD.encodeToString(toFixedLength(ecPublicKey.getW().getAffineY())));
        return jwk;
    }

    private static byte[] toFixedLength(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        byte[] fixed = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, fixed, 0, 32);
        } else {
            System.arraycopy(raw, 0, fixed, 32 - raw.length, raw.length);
        }
        return fixed;
    }
}
