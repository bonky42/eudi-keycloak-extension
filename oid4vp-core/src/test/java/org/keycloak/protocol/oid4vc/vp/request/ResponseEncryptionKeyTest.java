package org.keycloak.protocol.oid4vc.vp.request;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseEncryptionKeyTest {

    @Test
    void survivesTheSerializationRoundTrip() {
        ResponseEncryptionKey original = ResponseEncryptionKey.generate();

        ResponseEncryptionKey restored = ResponseEncryptionKey.restore(
            original.kid(), original.privateKeyB64(), original.publicKeyB64());

        assertEquals(original.kid(), restored.kid());
        assertEquals(original.privateKey(), restored.privateKey());
        assertEquals(original.publicJwk(), restored.publicJwk());
    }

    @Test
    void publicJwkDescribesAnEncryptionKeyOnP256() {
        ObjectNode jwk = ResponseEncryptionKey.generate().publicJwk();

        assertEquals("EC", jwk.get("kty").asText());
        assertEquals("P-256", jwk.get("crv").asText());
        assertEquals("enc", jwk.get("use").asText());
        assertEquals("ECDH-ES", jwk.get("alg").asText());
        // P-256 coordinates are exactly 32 bytes, left-padded — a shorter x or y is the classic
        // interop bug: some peers reject a 31-byte coordinate outright.
        assertEquals(32, Base64.getUrlDecoder().decode(jwk.get("x").asText()).length);
        assertEquals(32, Base64.getUrlDecoder().decode(jwk.get("y").asText()).length);
        assertTrue(jwk.get("kid").asText().length() >= 16);
    }

    @Test
    void twoTransactionsNeverShareAKey() {
        ResponseEncryptionKey a = ResponseEncryptionKey.generate();
        ResponseEncryptionKey b = ResponseEncryptionKey.generate();

        assertNotEquals(a.kid(), b.kid());
        assertNotEquals(a.privateKeyB64(), b.privateKeyB64());
    }
}
