package org.keycloak.protocol.oid4vc.vp.request;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.verifier.EcJose;
import org.keycloak.protocol.oid4vc.vp.verifier.EncryptedResponse;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Base64;

/**
 * Builds the OID4VP Request Object (an ES256-signed JWT, {@code typ=oauth-authz-req+jwt}) that the
 * verifier serves to the wallet: the verifier's identity, the {@code direct_post.jwt} response mode
 * along with the transaction's own ephemeral encryption key (the {@code client_metadata} claim),
 * the {@link PresentationTransaction}'s nonce and state, and the DCQL query itself embedded as a
 * JSON object (the {@code dcql_query} claim).
 */
public final class RequestObjectBuilder {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final String SELF_ISSUED_AUD = "https://self-issued.me/v2";

    private final KeyPair signerKey;
    private final X509Certificate signerCert;
    private final Clock clock;

    public RequestObjectBuilder(KeyPair signerKey, X509Certificate signerCert, Clock clock) {
        this.signerKey = signerKey;
        this.signerCert = signerCert;
        this.clock = clock;
    }

    /**
     * Builds and signs the Request Object for the given transaction.
     *
     * @param tx          the transaction supplying {@code nonce}, {@code state} and the DCQL query
     *                    ({@code dcqlQueryJson})
     * @param clientId    the verifier's identifier (the {@code client_id} claim)
     * @param responseUri where the {@code vp_token} is posted back (the {@code response_uri} claim)
     * @param ttlSeconds  validity in seconds, added to {@code iat} to produce {@code exp}
     * @return the ES256-signed compact JWT
     */
    public String build(PresentationTransaction tx, String clientId, String responseUri, int ttlSeconds) {
        try {
            ObjectNode header = MAPPER.createObjectNode();
            header.put("typ", "oauth-authz-req+jwt");
            header.put("alg", "ES256");
            ArrayNode x5c = MAPPER.createArrayNode();
            x5c.add(Base64.getEncoder().encodeToString(signerCert.getEncoded()));
            header.set("x5c", x5c);

            long iat = clock.instant().getEpochSecond();
            long exp = iat + ttlSeconds;

            JsonNode dcqlQueryNode = MAPPER.readTree(tx.getDcqlQueryJson());

            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("client_id", clientId);
            payload.put("response_type", "vp_token");
            payload.put("response_mode", "direct_post.jwt");
            payload.set("client_metadata", clientMetadata(tx));
            payload.put("response_uri", responseUri);
            payload.put("nonce", tx.getNonce());
            payload.put("state", tx.getState());
            payload.set("dcql_query", dcqlQueryNode);
            payload.put("iat", iat);
            payload.put("exp", exp);
            payload.put("aud", SELF_ISSUED_AUD);

            String headerB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(header));
            String payloadB64 = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(payload));
            String signingInput = headerB64 + "." + payloadB64;

            String signatureB64 = EcJose.sign(signerKey.getPrivate(), signingInput);
            return signingInput + "." + signatureB64;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build request object", e);
        }
    }

    /**
     * dc+sd-jwt is the only Credential Format this verifier's DCQL queries and its
     * {@code SdJwtVpVerifier} understand, and that verifier only ever accepts an ES256-signed
     * issuer-JWT and KB-JWT ({@code SdJwtVpVerifier.verifyEs256}) — so that is exactly what is
     * declared here, not copied from a spec example.
     */
    private static final String[] ES256_ONLY = {"ES256"};

    private ObjectNode clientMetadata(PresentationTransaction tx) {
        ArrayNode keys = MAPPER.createArrayNode();
        keys.add(tx.responseEncryptionKey().publicJwk());

        ObjectNode jwks = MAPPER.createObjectNode();
        jwks.set("keys", keys);

        ArrayNode encValues = MAPPER.createArrayNode();
        // Both values are advertised because the profile requires it: the wallet picks the
        // enc, and SHOULD pick A256GCM. We must therefore be able to open either — bound to a
        // single source of truth shared with the accept-check in EncryptedResponse, so the two
        // can never silently drift apart (see EncryptedResponse#SUPPORTED_ENC_VALUES).
        EncryptedResponse.SUPPORTED_ENC_VALUES.forEach(encValues::add);

        ObjectNode metadata = MAPPER.createObjectNode();
        metadata.set("jwks", jwks);
        metadata.set("encrypted_response_enc_values_supported", encValues);
        metadata.set("vp_formats_supported", vpFormatsSupported());
        return metadata;
    }

    /**
     * OID4VP 1.0 §11.1 declares {@code vp_formats_supported} REQUIRED Verifier metadata; §5.1
     * requires it in {@code client_metadata} specifically "when not available to the Wallet via
     * another mechanism" — which is always true here, since {@link VerifierClientId} derives
     * {@code client_id} as {@code x509_hash:<fingerprint>} rather than pointing at a federation
     * entity statement or any other side channel the wallet could consult instead.
     *
     * <p>The per-format sub-fields ({@code sd-jwt_alg_values}, {@code kb-jwt_alg_values}) are
     * themselves OPTIONAL (OID4VP 1.0 Appendix B.3.4); they are included anyway, set to exactly
     * what this verifier accepts (see {@link #ES256_ONLY}), so a wallet can skip presenting a
     * credential it already knows we could not verify.
     */
    private ObjectNode vpFormatsSupported() {
        ArrayNode sdJwtAlgs = MAPPER.createArrayNode();
        for (String alg : ES256_ONLY) {
            sdJwtAlgs.add(alg);
        }
        ArrayNode kbJwtAlgs = MAPPER.createArrayNode();
        for (String alg : ES256_ONLY) {
            kbJwtAlgs.add(alg);
        }

        ObjectNode dcSdJwt = MAPPER.createObjectNode();
        dcSdJwt.set("sd-jwt_alg_values", sdJwtAlgs);
        dcSdJwt.set("kb-jwt_alg_values", kbJwtAlgs);

        ObjectNode vpFormats = MAPPER.createObjectNode();
        vpFormats.set("dc+sd-jwt", dcSdJwt);
        return vpFormats;
    }
}
