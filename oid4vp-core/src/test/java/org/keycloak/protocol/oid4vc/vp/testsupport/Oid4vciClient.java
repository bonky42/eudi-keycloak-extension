package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.protocol.oid4vc.vp.verifier.EcJose;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The RECEIVING side of an OID4VCI wallet: resolves a credential offer, exchanges the
 * pre-authorized code, proves possession of the holder key, and collects the issued credential. It
 * knows nothing of PRESENTATION — see {@link SimulatedWallet}.
 *
 * <p>The key passed to {@link #fetchCredential} is the one that lands in the card's {@code cnf}, so
 * it MUST be the same key that later signs the KB-JWT, or holder binding fails.</p>
 */
public final class Oid4vciClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final String PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

    public record Offer(String credentialIssuer, List<String> configurationIds, String preAuthorizedCode) {
    }

    private final HttpClient http;

    public Oid4vciClient(HttpClient http) {
        this.http = http;
    }

    /** Extrait la valeur de {@code credential_offer_uri} d'une URI de wallet. */
    public static String offerUriFromWalletUri(String walletUri) {
        Matcher matcher = Pattern.compile("[?&]credential_offer_uri=([^&]+)").matcher(walletUri);
        if (!matcher.find()) {
            throw new IllegalArgumentException("no credential_offer_uri in " + walletUri);
        }
        return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
    }

    public static Offer parseOffer(String offerJson) {
        try {
            JsonNode offer = MAPPER.readTree(offerJson);
            List<String> ids = new ArrayList<>();
            for (JsonNode id : offer.path("credential_configuration_ids")) {
                ids.add(id.asText());
            }
            String preAuthCode = offer.path("grants").path(PRE_AUTH_GRANT).path("pre-authorized_code").asText(null);
            return new Offer(offer.path("credential_issuer").asText(null), ids, preAuthCode);
        } catch (Exception e) {
            throw new IllegalStateException("failed to parse credential offer: " + offerJson, e);
        }
    }

    /** OID4VCI proof of possession: an ES256-signed {@code openid4vci-proof+jwt}, public key in
     *  the header. */
    public static String buildJwtProof(KeyPair holderKey, String audience, String cNonce, long iat) {
        try {
            ObjectNode header = MAPPER.createObjectNode();
            header.put("typ", "openid4vci-proof+jwt");
            header.put("alg", "ES256");
            header.set("jwk", EcJwk.publicJwk(holderKey.getPublic()));

            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("aud", audience);
            payload.put("iat", iat);
            if (cNonce != null) {
                payload.put("nonce", cNonce);
            }

            String signingInput = B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(header))
                + "." + B64URL_NOPAD.encodeToString(MAPPER.writeValueAsBytes(payload));
            // ES256/JOSE-P1363 signing delegated to EcJose, already used here for verification
            return signingInput + "." + EcJose.sign(holderKey.getPrivate(), signingInput);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to build OID4VCI proof", e);
        }
    }

    /**
     * The full sequence: offer, metadata, pre-authorized code, nonce, credential.
     *
     * @return the SD-JWT VC received: issuer JWT plus disclosures, with no KB-JWT
     */
    public String fetchCredential(String credentialOfferUri, KeyPair holderKey) {
        Offer offer = parseOffer(get(credentialOfferUri));

        JsonNode metadata = readTree(
            get(offer.credentialIssuer() + "/.well-known/openid-credential-issuer"));
        String credentialEndpoint = metadata.path("credential_endpoint").asText();
        String nonceEndpoint = metadata.path("nonce_endpoint").asText();

        JsonNode token = readTree(form(
            offer.credentialIssuer() + "/protocol/openid-connect/token",
            "grant_type=" + enc(PRE_AUTH_GRANT) + "&pre-authorized_code=" + enc(offer.preAuthorizedCode()),
            null));
        String accessToken = token.path("access_token").asText();

        String cNonce = readTree(form(nonceEndpoint, "", accessToken)).path("c_nonce").asText(null);

        String proof = buildJwtProof(holderKey, offer.credentialIssuer(), cNonce,
            System.currentTimeMillis() / 1000);
        ObjectNode request = MAPPER.createObjectNode();
        // When the issuer returns `authorization_details` carrying `credential_identifiers`, the
        // specification and Keycloak both REQUIRE the request to name the card by identifier rather
        // than by configuration: that is what ties it to the grant already recorded.
        String credentialIdentifier = firstCredentialIdentifier(token);
        if (credentialIdentifier != null) {
            request.put("credential_identifier", credentialIdentifier);
        } else {
            request.put("credential_configuration_id", offer.configurationIds().get(0));
        }
        request.putObject("proofs").putArray("jwt").add(proof);

        JsonNode response = readTree(postJson(credentialEndpoint, request.toString(), accessToken));
        JsonNode credentials = response.path("credentials");
        if (credentials.isArray() && !credentials.isEmpty()) {
            return credentials.get(0).path("credential").asText();
        }
        return response.path("credential").asText();
    }

    /** The token's first {@code authorization_details[].credential_identifiers[0]}, or
     *  {@code null} if the issuer publishes none. */
    private static String firstCredentialIdentifier(JsonNode tokenResponse) {
        for (JsonNode detail : tokenResponse.path("authorization_details")) {
            JsonNode identifiers = detail.path("credential_identifiers");
            if (identifiers.isArray() && !identifiers.isEmpty()) {
                return identifiers.get(0).asText();
            }
        }
        return null;
    }

    // ---- HTTP -----------------------------------------------------------------

    private String get(String url) {
        return send(HttpRequest.newBuilder(URI.create(url)).header("Accept", "application/json").GET());
    }

    private String form(String url, String body, String bearer) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return send(builder);
    }

    private String postJson(String url, String body, String bearer) {
        return send(HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", "Bearer " + bearer)
            .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    private String send(HttpRequest.Builder builder) {
        try {
            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 400) {
                throw new IllegalStateException("OID4VCI call failed: " + response.statusCode()
                    + " " + response.uri() + " -> " + response.body());
            }
            return response.body();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("OID4VCI call failed", e);
        }
    }

    private static JsonNode readTree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("invalid JSON: " + json, e);
        }
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
