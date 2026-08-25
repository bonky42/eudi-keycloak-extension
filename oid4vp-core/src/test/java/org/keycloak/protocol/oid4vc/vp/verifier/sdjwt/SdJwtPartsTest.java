package org.keycloak.protocol.oid4vc.vp.verifier.sdjwt;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestCredentialIssuer;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;

import java.security.KeyPair;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SdJwtPartsTest {

    private static final String FAKE_KB_JWT = "aaa.bbb.ccc";

    private String issueTestSdJwt() {
        TestTrustChain chain = new TestTrustChain();
        TestCredentialIssuer issuer = new TestCredentialIssuer(chain);
        KeyPair holder = issuer.newHolderKeyPair();
        return issuer.issue("urn:eudi:pid:1",
            Map.of("given_name", "Marie", "age_over_18", true),
            holder.getPublic(), 1000L, 999_999_999L);
    }

    @Test
    void parsesPresentationWithKbJwt() throws Exception {
        String issued = issueTestSdJwt(); // ends with "~"
        assertTrue(issued.endsWith("~"));

        String withKb = issued + FAKE_KB_JWT;

        SdJwtParts parts = SdJwtParts.parse(withKb);

        assertEquals(2, parts.disclosures().size());
        assertEquals(FAKE_KB_JWT, parts.kbJwt());
        assertEquals("urn:eudi:pid:1", parts.issuerPayload().get("vct").asText());
        assertEquals(issued, parts.presentationWithoutKb());
    }

    @Test
    void parsesIssuerOnlyPresentation() throws Exception {
        String issued = issueTestSdJwt(); // ends with "~", no kb-jwt

        SdJwtParts parts = SdJwtParts.parse(issued);

        assertNull(parts.kbJwt());
        assertEquals(2, parts.disclosures().size());
        assertEquals(issued, parts.presentationWithoutKb());
    }

    @Test
    void issuerJwtAndHeaderAreExposed() throws Exception {
        String issued = issueTestSdJwt();
        SdJwtParts parts = SdJwtParts.parse(issued);

        String expectedIssuerJwt = issued.substring(0, issued.indexOf('~'));
        assertEquals(expectedIssuerJwt, parts.issuerJwt());
        assertEquals("ES256", parts.issuerHeader().get("alg").asText());
        assertEquals("dc+sd-jwt", parts.issuerHeader().get("typ").asText());
    }

    @Test
    void rejectsTokenWithoutTilde() {
        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> SdJwtParts.parse("garbage"));
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
    }

    @Test
    void rejectsEmptyString() {
        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> SdJwtParts.parse(""));
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
    }

    @Test
    void rejectsIssuerJwtWithOnlyTwoSegments() {
        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> SdJwtParts.parse("aaa.bbb~"));
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
    }

    @Test
    void rejectsDisclosureThatDecodesToJsonObject() throws Exception {
        String issued = issueTestSdJwt();
        String issuerJwt = issued.substring(0, issued.indexOf('~'));

        String badDisclosure = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"not\":\"an-array\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        String tokenWithBadDisclosure = issuerJwt + "~" + badDisclosure + "~";

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> SdJwtParts.parse(tokenWithBadDisclosure));
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
    }

    @Test
    void rejectsDisclosureThatIsNotValidJson() throws Exception {
        String issued = issueTestSdJwt();
        String issuerJwt = issued.substring(0, issued.indexOf('~'));

        String badDisclosure = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString("not-json-at-all".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        String tokenWithBadDisclosure = issuerJwt + "~" + badDisclosure + "~";

        VpVerificationException ex = assertThrows(VpVerificationException.class,
            () -> SdJwtParts.parse(tokenWithBadDisclosure));
        assertEquals(VpErrorCode.PARSING_ERROR, ex.getCode());
    }
}
