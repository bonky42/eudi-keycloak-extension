package org.keycloak.protocol.oid4vc.vp.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimulatedWalletTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final long NOW = 1_000_000L;

    /** The vct this wallet never received through {@link SimulatedWallet#receive}: OUR card. */
    private static final String OWN_VCT = "urn:pn:account-holder:1";

    /** A query with two OPTIONAL sets, one for a national PID and one for the card this Keycloak
     *  issues itself: the unified shape. */
    private static final String UNIFIED_QUERY = """
        {
          "credentials": [
            { "id": "pid", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ { "path": ["given_name"] }, { "path": ["age_over_18"] } ] },
            { "id": "own", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:pn:account-holder:1"] },
              "claims": [ { "path": ["sub"] } ] }
          ],
          "credential_sets": [
            { "required": false, "options": [ ["pid"] ] },
            { "required": false, "options": [ ["own"] ] }
          ]
        }""";

    private TestCredentialIssuer issuer;
    private SimulatedWallet wallet;

    @BeforeEach
    void setUp() {
        issuer = new TestCredentialIssuer(new TestTrustChain());
        wallet = new SimulatedWallet(issuer, Map.of("sub", "PID-1", "given_name", "Marie", "age_over_18", true));
    }

    /** A minimal, unsigned Request Object: the wallet does not verify the signature. */
    private static String requestObject(String vct, String nonce) {
        String header = B64URL_NOPAD.encodeToString("{\"alg\":\"ES256\"}".getBytes());
        String payload = B64URL_NOPAD.encodeToString(("""
            {"nonce":"%s","client_id":"x509_san_dns:kc.example","state":"ST","iat":%d,
             "dcql_query":{"credentials":[{"id":"c","format":"dc+sd-jwt",
                            "meta":{"vct_values":["%s"]}}]}}""".formatted(nonce, NOW, vct)).getBytes());
        return header + "." + payload + ".SIG";
    }

    /** A minimal, unsigned Request Object carrying {@code dcqlQueryJson} as is. */
    private static String requestObject(String dcqlQueryJson) {
        String header = B64URL_NOPAD.encodeToString("{\"alg\":\"ES256\"}".getBytes());
        String payload = B64URL_NOPAD.encodeToString(("""
            {"nonce":"N1","client_id":"x509_san_dns:kc.example","state":"ST","iat":%d,
             "dcql_query":%s}""".formatted(NOW, dcqlQueryJson)).getBytes());
        return header + "." + payload + ".SIG";
    }

    @Test
    void heldCredentialIsPresentedInsteadOfForgingANewOne() throws Exception {
        String held = issuer.issue(OWN_VCT, Map.of("sub", "https://iss:PID-1"),
            wallet.holderKeyPair().getPublic(), 999_000L, 2_000_000L);
        wallet.receive(OWN_VCT, held);

        assertTrue(wallet.holds(OWN_VCT));
        JsonNode vpToken = MAPPER.readTree(
            wallet.respondTo(requestObject(OWN_VCT, "N1"), SimulatedWallet.Tamper.NONE));
        String presented = vpToken.get("c").get(0).asText();
        assertTrue(presented.startsWith(held),
            "the HELD card must be presented as is, followed by the KB-JWT");
    }

    @Test
    void unheldVctStillFallsBackToForgingThePid() throws Exception {
        assertFalse(wallet.holds("urn:eudi:pid:1"));
        JsonNode vpToken = MAPPER.readTree(
            wallet.respondTo(requestObject("urn:eudi:pid:1", "N2"), SimulatedWallet.Tamper.NONE));
        String presented = vpToken.get("c").get(0).asText();
        assertTrue(presented.contains("~"), "an SD-JWT presentation is produced even with no held card");
    }

    @Test
    void respondsWithTheOid4vp10ObjectForm() throws Exception {
        JsonNode vpToken = MAPPER.readTree(wallet.respondTo(requestObject(UNIFIED_QUERY), SimulatedWallet.Tamper.NONE));
        assertTrue(vpToken.isObject(), "OID4VP 1.0 section 8.1: the vp_token is an OBJECT");
        assertTrue(vpToken.get("pid").isArray());
        assertEquals(1, vpToken.get("pid").size(), "`multiple` was not asked for");
        assertTrue(vpToken.get("pid").get(0).isTextual());
    }

    @Test
    void omitsTheKeyOfACardItDoesNotHold() throws Exception {
        JsonNode vpToken = MAPPER.readTree(wallet.respondTo(requestObject(UNIFIED_QUERY), SimulatedWallet.Tamper.NONE));
        assertFalse(vpToken.has("own"),
            "no entry for an unsatisfied optional query — and above all, the wallet must NOT forge "
                + "a card it never received");
    }

    @Test
    void presentsBothOnceItHoldsTheCard() throws Exception {
        wallet.receive(OWN_VCT, issuer.issue(OWN_VCT, Map.of("sub", "FED-1"),
            wallet.holderKeyPair().getPublic(), NOW - 10, NOW + 100_000));

        JsonNode vpToken = MAPPER.readTree(wallet.respondTo(requestObject(UNIFIED_QUERY), SimulatedWallet.Tamper.NONE));
        assertTrue(vpToken.has("pid"));
        assertTrue(vpToken.has("own"));
    }

    @Test
    void mislabelledKeyPutsThePidUnderTheOtherQueryId() throws Exception {
        JsonNode vpToken = MAPPER.readTree(
            wallet.respondTo(requestObject(UNIFIED_QUERY), SimulatedWallet.Tamper.MISLABELLED_KEY));
        assertTrue(vpToken.has("own"));
        assertFalse(vpToken.has("pid"));
    }
}
