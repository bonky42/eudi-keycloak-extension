package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestedClaimsTest {

    private static final String UNIFIED = """
        {"credentials":[
          {"id":"own","format":"dc+sd-jwt","meta":{"vct_values":["urn:pn:account-holder:1"]},
           "claims":[{"path":["sub"]}]},
          {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
           "claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["sub"]}]}]}""";

    @Test
    void collectsEveryClaimOnceInEncounterOrder() {
        assertEquals(List.of("sub", "given_name", "family_name"),
            RequestedClaims.of(DcqlQuery.fromJson(UNIFIED)),
            "a claim asked for by two credential queries is named once, not twice");
    }

    @Test
    void aQueryWithoutClaimsContributesNothing() {
        DcqlQuery query = DcqlQuery.fromJson("""
            {"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}""");
        assertTrue(RequestedClaims.of(query).isEmpty());
    }

    @Test
    void nullAndEmptyAreNeverNull() {
        assertTrue(RequestedClaims.of(null).isEmpty());
        assertTrue(RequestedClaims.of(DcqlQuery.fromJson("{}")).isEmpty());
    }

    @Test
    void onlyTheFirstPathSegmentNamesTheClaim() {
        DcqlQuery query = DcqlQuery.fromJson("""
            {"credentials":[{"id":"pid","claims":[{"path":["address","locality"]}]}]}""");
        assertEquals(List.of("address"), RequestedClaims.of(query),
            "the page names the claim, not the path into it");
    }

    @Test
    void aBlankOrEmptyPathIsIgnoredRatherThanNamed() {
        DcqlQuery query = DcqlQuery.fromJson("""
            {"credentials":[{"id":"pid","claims":[
              {"path":[]},{"path":["  "]},{"path":["email"]}]}]}""");
        assertEquals(List.of("email"), RequestedClaims.of(query),
            "an empty entry would render as a bullet with no text, which reads as a defect");
    }
}
