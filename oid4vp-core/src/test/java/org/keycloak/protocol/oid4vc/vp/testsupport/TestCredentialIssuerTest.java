package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TestCredentialIssuerTest {

    @Test
    void issuesParsableSdJwt() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();

        String sdJwt = issuer.issue("urn:eudi:pid:1",
            Map.of("given_name", "Marie", "age_over_18", true),
            holder.getPublic(), 1000L, 999_999_999L);

        String[] parts = sdJwt.split("~");
        assertEquals(3, parts.length); // issuer-jwt + 2 disclosures (se termine par ~)
        assertTrue(sdJwt.endsWith("~"));

        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[0].split("\\.")[1]));
        JsonNode payload = new ObjectMapper().readTree(payloadJson);
        assertEquals("urn:eudi:pid:1", payload.get("vct").asText());
        assertEquals(2, payload.get("_sd").size());
        assertEquals("sha-256", payload.get("_sd_alg").asText());
        assertNotNull(payload.get("cnf").get("jwk"));
    }
}
