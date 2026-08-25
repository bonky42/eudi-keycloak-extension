package org.keycloak.protocol.oid4vc.vp.verifier;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** OID4VP 1.0 section 8.1: the vp_token is an object keyed by credential query id. */
class VpTokenResponseTest {

    private static final DcqlQuery QUERY = DcqlQuery.fromJson("""
        {"credentials":[
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},
          {"id":"own","format":"dc+sd-jwt","meta":{"vct_values":["urn:pn:account-holder:1"]}}]}""");

    @Test
    void parsesASingleEntry() throws Exception {
        VpTokenResponse response = VpTokenResponse.parse("{\"pid\":[\"eyJ.aaa~kb\"]}", QUERY);
        assertEquals(List.of("pid"), List.copyOf(response.presentations().keySet()));
        assertEquals("eyJ.aaa~kb", response.presentations().get("pid"));
    }

    @Test
    void parsesTwoEntriesInOrder() throws Exception {
        VpTokenResponse response =
            VpTokenResponse.parse("{\"pid\":[\"a~kb\"],\"own\":[\"b~kb\"]}", QUERY);
        assertEquals(List.of("pid", "own"), List.copyOf(response.presentations().keySet()));
    }

    @Test
    void anAbsentOptionalKeyIsNormal() throws Exception {
        // §8.1 : « There MUST NOT be any entry […] for optional Credential Queries when there are
        // no matching Credentials » — l'absence est la forme CONFORME du « je n'ai pas cette carte ».
        assertEquals(1, VpTokenResponse.parse("{\"own\":[\"b~kb\"]}", QUERY).presentations().size());
    }

    @Test
    void anEmptyObjectParsesAndIsEmpty() throws Exception {
        assertTrue(VpTokenResponse.parse("{}", QUERY).presentations().isEmpty(),
            "a wallet holding nothing may legitimately return an empty object; deciding the login "
                + "is refused belongs to the engine, not the parser");
    }

    @Test
    void refusesAKeyTheQueryNeverDeclared() {
        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("{\"inconnue\":[\"a~kb\"]}", QUERY));
        assertEquals(VpErrorCode.UNKNOWN_RESPONSE_KEY, e.getCode());
    }

    @Test
    void refusesMoreThanOnePresentationUnderOneKey() {
        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("{\"pid\":[\"a~kb\",\"b~kb\"]}", QUERY));
        assertEquals(VpErrorCode.TOO_MANY_PRESENTATIONS, e.getCode(),
            "`multiple` is never set, so its false default allows exactly ONE presentation");
    }

    @Test
    void refusesTheLegacyBareStringForm() {
        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("eyJ.aaa~kb", QUERY));
        assertEquals(VpErrorCode.PARSING_ERROR, e.getCode(),
            "the older bare-string form is emitted by NO conformant wallet: accepting it would "
                + "keep alive a path that no longer exists");
    }

    @Test
    void refusesAJsonStringThatIsNotAnObject() {
        // "eyJ.aaa~kb" above is not valid JSON at all — the dot breaks parsing first. This test
        // covers the `!root.isObject()` guard proper, on JSON that IS valid but is a string.
        VpVerificationException e = assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("\"eyJhbGciOiJFUzI1NiJ9.aaa~kb\"", QUERY));
        assertEquals(VpErrorCode.PARSING_ERROR, e.getCode());
    }

    @Test
    void refusesAnEmptyArrayAndANonStringPresentation() {
        assertEquals(VpErrorCode.PARSING_ERROR, assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("{\"pid\":[]}", QUERY)).getCode());
        assertEquals(VpErrorCode.PARSING_ERROR, assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("{\"pid\":[{\"x\":1}]}", QUERY)).getCode());
    }

    @Test
    void refusesGarbageAndNull() {
        assertEquals(VpErrorCode.PARSING_ERROR, assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse("{pas du json", QUERY)).getCode());
        assertEquals(VpErrorCode.PARSING_ERROR, assertThrows(VpVerificationException.class,
            () -> VpTokenResponse.parse(null, QUERY)).getCode());
    }
}
