package org.keycloak.protocol.oid4vc.vp.request;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestJwe;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.verifier.EcJose;
import org.keycloak.protocol.oid4vc.vp.verifier.EncryptedResponse;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RequestObjectBuilder} produces an ES256-signed OID4VP Request Object with the expected
 * claims, {@code dcql_query} among them as a nested JSON object rather than a string.
 */
class RequestObjectBuilderTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(RequestObjectBuilderTest.class.getClassLoader());
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    private static final long NOW = 2_000_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);

    private static final String PID_QUERY_JSON = """
        {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [
                { "path": ["given_name"] },
                { "path": ["age_over_18"] }
              ]
            }
          ]
        }""";

    @Test
    void buildsSignedRequestObjectWithExpectedClaims() throws Exception {
        TestTrustChain chain = new TestTrustChain();

        PresentationTransaction tx = new PresentationTransaction();
        tx.setId("tx-1");
        tx.setNonce("test-nonce-123");
        tx.setState("test-state-456");
        tx.setDcqlQueryJson(PID_QUERY_JSON);
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(NOW);

        ResponseEncryptionKey encryptionKey = ResponseEncryptionKey.generate();
        tx.setResponseEncKid(encryptionKey.kid());
        tx.setResponseEncPrivateKey(encryptionKey.privateKeyB64());
        tx.setResponseEncPublicKey(encryptionKey.publicKeyB64());

        RequestObjectBuilder builder = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK);

        int ttlSeconds = 300;
        String jwt = builder.build(tx, "test-client-app", "https://verifier.example.org/direct_post", ttlSeconds);

        String[] segments = jwt.split("\\.", -1);
        assertEquals(3, segments.length);

        JsonNode header = MAPPER.readTree(B64URL.decode(segments[0]));
        assertEquals("oauth-authz-req+jwt", header.get("typ").asText());
        assertEquals("ES256", header.get("alg").asText());
        assertTrue(header.has("x5c"));
        assertTrue(header.get("x5c").isArray());
        assertFalse(header.get("x5c").isEmpty());

        JsonNode payload = MAPPER.readTree(B64URL.decode(segments[1]));
        assertEquals("test-client-app", payload.get("client_id").asText());
        assertEquals("vp_token", payload.get("response_type").asText());
        assertEquals("direct_post.jwt", payload.get("response_mode").asText());
        assertEquals("https://verifier.example.org/direct_post", payload.get("response_uri").asText());
        assertEquals("test-nonce-123", payload.get("nonce").asText());
        assertEquals("test-state-456", payload.get("state").asText());
        assertEquals("https://self-issued.me/v2", payload.get("aud").asText());

        JsonNode dcqlQuery = payload.get("dcql_query");
        assertTrue(dcqlQuery.isObject());
        assertEquals("pid", dcqlQuery.get("credentials").get(0).get("id").asText());

        long iat = payload.get("iat").asLong();
        long exp = payload.get("exp").asLong();
        assertEquals(NOW, iat);
        assertEquals(ttlSeconds, exp - iat);

        String signingInput = segments[0] + "." + segments[1];
        assertTrue(EcJose.verify(chain.issuerKeyPair.getPublic(), signingInput, segments[2]));
    }

    @Test
    void announcesEncryptedResponseModeAndAnEphemeralKey() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationTransaction tx = transactionWithEncryptionKey();

        String jwt = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK)
            .build(tx, "test-client-app", "https://verifier.example.org/direct_post", 300);
        JsonNode payload = MAPPER.readTree(B64URL.decode(jwt.split("\\.", -1)[1]));

        assertEquals("direct_post.jwt", payload.get("response_mode").asText());

        JsonNode metadata = payload.get("client_metadata");
        assertNotNull(metadata, "HAIP requires the ephemeral key to travel in client_metadata");

        JsonNode encValues = metadata.get("encrypted_response_enc_values_supported");
        assertEquals(2, encValues.size(),
            "the profile requires BOTH A128GCM and A256GCM to be advertised; the wallet chooses");
        assertTrue(encValues.toString().contains("A128GCM"));
        assertTrue(encValues.toString().contains("A256GCM"));

        JsonNode jwk = metadata.get("jwks").get("keys").get(0);
        assertEquals("EC", jwk.get("kty").asText());
        assertEquals("P-256", jwk.get("crv").asText());
        assertEquals("enc", jwk.get("use").asText());
        assertEquals(tx.getResponseEncKid(), jwk.get("kid").asText());
    }

    /**
     * OID4VP 1.0 §11.1 declares {@code vp_formats_supported} REQUIRED Verifier metadata, and §5.1
     * requires it in {@code client_metadata} "when not available to the Wallet via another
     * mechanism" — true here, since this verifier's {@code client_id} is {@code x509_hash}
     * ({@link VerifierClientId}), with no federation entity statement or other side channel the
     * wallet could use instead. The per-format sub-fields {@code sd-jwt_alg_values} and
     * {@code kb-jwt_alg_values} are themselves OPTIONAL (Appendix B.3.4), but since this verifier
     * only ever accepts an ES256-signed issuer-JWT and KB-JWT ({@code SdJwtVpVerifier.verifyEs256}),
     * advertising exactly that (rather than omitting the sub-fields) tells a wallet upfront what
     * it can skip presenting.
     */
    @Test
    void clientMetadataDeclaresVpFormatsSupportedForDcSdJwt() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationTransaction tx = transactionWithEncryptionKey();

        String jwt = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK)
            .build(tx, "test-client-app", "https://verifier.example.org/direct_post", 300);
        JsonNode payload = MAPPER.readTree(B64URL.decode(jwt.split("\\.", -1)[1]));

        JsonNode vpFormats = payload.get("client_metadata").get("vp_formats_supported");
        assertNotNull(vpFormats, "OID4VP 1.0 §11.1 makes vp_formats_supported REQUIRED Verifier "
            + "metadata, and this verifier has no other channel (no federation entity statement) "
            + "through which the wallet could learn it");

        JsonNode dcSdJwt = vpFormats.get("dc+sd-jwt");
        assertNotNull(dcSdJwt, "the only format this verifier's DCQL queries and SdJwtVpVerifier "
            + "understand is dc+sd-jwt");

        JsonNode sdJwtAlgs = dcSdJwt.get("sd-jwt_alg_values");
        assertNotNull(sdJwtAlgs);
        assertEquals(1, sdJwtAlgs.size());
        assertEquals("ES256", sdJwtAlgs.get(0).asText(),
            "SdJwtVpVerifier only ever verifies an ES256-signed issuer-JWT");

        JsonNode kbJwtAlgs = dcSdJwt.get("kb-jwt_alg_values");
        assertNotNull(kbJwtAlgs);
        assertEquals(1, kbJwtAlgs.size());
        assertEquals("ES256", kbJwtAlgs.get(0).asText(),
            "SdJwtVpVerifier only ever verifies an ES256-signed KB-JWT (verifyEs256)");
    }

    /**
     * Pins the property the whole response-encryption design rests on: the transaction's
     * PRIVATE encryption key never travels in the Request Object. Only the public key belongs
     * in {@code client_metadata.jwks} (see {@link #announcesEncryptedResponseModeAndAnEphemeralKey}) —
     * the private half must stay server-side, decrypting only what the wallet later seals to the
     * matching public key.
     */
    @Test
    void thePrivateEncryptionKeyNeverReachesTheRequestObject() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationTransaction tx = transactionWithEncryptionKey();

        String jwt = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK)
            .build(tx, "test-client-app", "https://verifier.example.org/direct_post", 300);

        // Decode before searching. The payload is base64url of JSON while privateKeyB64() is
        // STANDARD base64 (its alphabet has + and /), so a leaked key could only ever appear as
        // base64-of-base64 — searching the compact JWT for the literal string can never match, and
        // an earlier version of this test passed even with the key deliberately embedded.
        String payload = new String(B64URL.decode(jwt.split("\\.", -1)[1]), StandardCharsets.UTF_8);
        assertFalse(payload.contains(tx.getResponseEncPrivateKey()),
            "the response-encryption private key must never appear in the outward-facing Request "
                + "Object. Payload was: " + payload);

        // And catch the likelier shape of the same leak: `d` is the private scalar of an EC JWK,
        // encoded as base64url — it would never appear as privateKeyB64 even unencoded.
        JsonNode jwk = MAPPER.readTree(payload).get("client_metadata").get("jwks").get("keys").get(0);
        assertFalse(jwk.has("d"),
            "the published JWK must carry only the public half; a `d` member is the private scalar: "
                + jwk);
    }

    @Test
    void twoAuthorizationRequestsNeverShareAnEncryptionKey() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        RequestObjectBuilder builder =
            new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK);

        JsonNode firstJwk = jwkOf(builder.build(transactionWithEncryptionKey(),
            "test-client-app", "https://verifier.example.org/direct_post", 300));
        JsonNode secondJwk = jwkOf(builder.build(transactionWithEncryptionKey(),
            "test-client-app", "https://verifier.example.org/direct_post", 300));

        assertNotEquals(firstJwk.get("x").asText(), secondJwk.get("x").asText(),
            "two Authorization Requests must not share an encryption key");
    }

    /**
     * Binds the advertised {@code encrypted_response_enc_values_supported} to what
     * {@link EncryptedResponse} actually accepts: reads the list out of a REAL built Request
     * Object (not the {@link EncryptedResponse#SUPPORTED_ENC_VALUES} constant directly — that
     * would only prove the constant equals itself), seals a response under EACH value it names,
     * and asserts every single one decrypts. If the two lists (advertise vs. accept) ever drift
     * apart again, this fails: either a value we advertise but no longer open, or the reverse.
     */
    @Test
    void everyAdvertisedEncValueActuallyDecrypts() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        PresentationTransaction tx = transactionWithEncryptionKey();

        String jwt = new RequestObjectBuilder(chain.issuerKeyPair, chain.issuerCert, CLOCK)
            .build(tx, "test-client-app", "https://verifier.example.org/direct_post", 300);
        JsonNode payload = MAPPER.readTree(B64URL.decode(jwt.split("\\.", -1)[1]));
        JsonNode encValues = payload.get("client_metadata").get("encrypted_response_enc_values_supported");

        List<String> advertised = new ArrayList<>();
        encValues.forEach(node -> advertised.add(node.asText()));
        assertFalse(advertised.isEmpty(), "the profile requires at least one enc value advertised");

        for (String enc : advertised) {
            String sealed = TestJwe.seal(tx.responseEncryptionKey().publicJwk(), enc,
                "{\"vp_token\":{\"pid\":[\"abc\"]},\"state\":\"ST\"}");

            EncryptedResponse.WalletResponse response =
                EncryptedResponse.decrypt(sealed, tx.responseEncryptionKey().privateKey());

            assertEquals("ST", response.state(), "advertised enc value " + enc + " must actually decrypt");
        }
    }

    private static JsonNode jwkOf(String requestObjectJwt) throws Exception {
        return MAPPER.readTree(B64URL.decode(requestObjectJwt.split("\\.", -1)[1]))
            .get("client_metadata").get("jwks").get("keys").get(0);
    }

    /** Builds a transaction the way the existing tests in this class do — inline, no helper — plus
     *  the encryption material the engine now mints in {@code createTransaction}. */
    private static PresentationTransaction transactionWithEncryptionKey() {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setId("tx-enc");
        tx.setNonce("test-nonce-123");
        tx.setState("test-state-456");
        tx.setDcqlQueryJson(PID_QUERY_JSON);
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(NOW);

        ResponseEncryptionKey key = ResponseEncryptionKey.generate();
        tx.setResponseEncKid(key.kid());
        tx.setResponseEncPrivateKey(key.privateKeyB64());
        tx.setResponseEncPublicKey(key.publicKeyB64());
        return tx;
    }
}
