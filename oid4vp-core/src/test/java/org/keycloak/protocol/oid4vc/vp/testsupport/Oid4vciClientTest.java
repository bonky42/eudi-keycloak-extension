package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.verifier.EcJose;

import java.security.KeyPair;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Oid4vciClientTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void offerUriIsExtractedFromWalletUri() {
        String walletUri = "openid-credential-offer://?credential_offer_uri="
            + "https%3A%2F%2Fkc.example%2Frealms%2Fr%2Fprotocol%2Foid4vc%2Fcredential-offer%2Fabc";
        assertEquals("https://kc.example/realms/r/protocol/oid4vc/credential-offer/abc",
            Oid4vciClient.offerUriFromWalletUri(walletUri));
    }

    @Test
    void offerJsonYieldsIssuerConfigurationIdsAndPreAuthCode() {
        String json = """
            {"credential_issuer":"https://kc.example/realms/r",
             "credential_configuration_ids":["account-holder"],
             "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
                       {"pre-authorized_code":"PRE-123"}}}""";
        Oid4vciClient.Offer offer = Oid4vciClient.parseOffer(json);
        assertEquals("https://kc.example/realms/r", offer.credentialIssuer());
        assertEquals(java.util.List.of("account-holder"), offer.configurationIds());
        assertEquals("PRE-123", offer.preAuthorizedCode());
    }

    @Test
    void jwtProofCarriesTypJwkAudienceAndNonceAndVerifiesWithHolderKey() throws Exception {
        KeyPair holder = new TestCredentialIssuer(new TestTrustChain()).newHolderKeyPair();

        String proof = Oid4vciClient.buildJwtProof(holder, "https://kc.example/realms/r", "C-NONCE", 1_000_000L);

        String[] segments = proof.split("\\.", -1);
        assertEquals(3, segments.length, "JWT compact attendu");
        JsonNode header = MAPPER.readTree(Base64.getUrlDecoder().decode(segments[0]));
        JsonNode payload = MAPPER.readTree(Base64.getUrlDecoder().decode(segments[1]));

        assertEquals("openid4vci-proof+jwt", header.path("typ").asText());
        assertEquals("ES256", header.path("alg").asText());
        assertEquals("EC", header.path("jwk").path("kty").asText(),
            "the holder key MUST travel in the header: it becomes the card's cnf");
        assertEquals("https://kc.example/realms/r", payload.path("aud").asText());
        assertEquals("C-NONCE", payload.path("nonce").asText());
        assertEquals(1_000_000L, payload.path("iat").asLong());

        assertTrue(EcJose.verify(holder.getPublic(), segments[0] + "." + segments[1], segments[2]),
            "the proof must be signed by the holder's private key");
    }
}
