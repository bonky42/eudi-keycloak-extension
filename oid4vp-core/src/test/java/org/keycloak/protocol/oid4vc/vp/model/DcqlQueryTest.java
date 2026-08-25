package org.keycloak.protocol.oid4vc.vp.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DcqlQueryTest {

    static final String PID_QUERY = """
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

    static final String UNIFIED_QUERY = """
        {
          "credentials": [
            { "id": "pid", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [ { "path": ["sub"] } ] },
            { "id": "own", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:pn:account-holder:1"] },
              "claims": [ { "path": ["sub"] } ] }
          ],
          "credential_sets": [
            { "required": false, "options": [ ["pid"] ] },
            { "required": false, "options": [ ["own"] ] }
          ]
        }""";

    @Test
    void parsesMinimalPidQuery() {
        DcqlQuery q = DcqlQuery.fromJson(PID_QUERY);
        assertEquals(1, q.getCredentials().size());
        DcqlQuery.CredentialQuery c = q.getCredentials().get(0);
        assertEquals("pid", c.getId());
        assertEquals("dc+sd-jwt", c.getFormat());
        assertEquals(java.util.List.of("urn:eudi:pid:1"), c.getMeta().getVctValues());
        assertEquals(java.util.List.of("given_name"), c.getClaims().get(0).getPath());
    }

    @Test
    void roundTripsToJson() {
        DcqlQuery q = DcqlQuery.fromJson(PID_QUERY);
        DcqlQuery q2 = DcqlQuery.fromJson(q.toJson());
        assertEquals("pid", q2.getCredentials().get(0).getId());
    }

    @Test
    void rejectsInvalidJson() {
        assertThrows(IllegalArgumentException.class, () -> DcqlQuery.fromJson("{not json"));
    }

    @Test
    void parsesTwoOptionalCredentialSets() {
        DcqlQuery q = DcqlQuery.fromJson(UNIFIED_QUERY);
        assertEquals(2, q.getCredentialSets().size());
        assertFalse(q.getCredentialSets().get(0).isRequiredOrDefault());
        assertEquals(java.util.List.of(java.util.List.of("pid")),
            q.getCredentialSets().get(0).getOptions());
    }

    @Test
    void anOmittedRequiredDefaultsToTrue() {
        DcqlQuery q = DcqlQuery.fromJson(
            "{\"credentials\":[],\"credential_sets\":[{\"options\":[[\"pid\"]]}]}");
        assertTrue(q.getCredentialSets().get(0).isRequiredOrDefault(),
            "OID4VP 1.0 §6.2 : `required` omis vaut true");
    }

    @Test
    void serializesTheSnakeCaseKeyAndOmitsItWhenAbsent() {
        assertTrue(DcqlQuery.fromJson(UNIFIED_QUERY).toJson().contains("\"credential_sets\""));
        assertFalse(DcqlQuery.fromJson(PID_QUERY).toJson().contains("credential_sets"),
            "an older query must still serialise exactly as it did before");
    }

    @Test
    void findsACredentialQueryById() {
        DcqlQuery q = DcqlQuery.fromJson(UNIFIED_QUERY);
        assertEquals("urn:pn:account-holder:1",
            q.credentialById("own").getMeta().getVctValues().get(0));
        assertNull(q.credentialById("inconnue"));
    }
}
