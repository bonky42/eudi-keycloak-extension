package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class VerifiedClaimsBuilderTest {

    @SuppressWarnings("unchecked")
    private static Map<String,Object> verification(Map<String,Object> vc) {
        return (Map<String,Object>) vc.get("verification");
    }

    @Test
    void buildsFullStructure() {
        Map<String,Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("age_over_18", true);
        Map<String,Object> vc = VerifiedClaimsBuilder.build(
            "https://issuer.example", "urn:eudi:pid:1", "dc+sd-jwt",
            "CN=Test CA", "2026-08-03T14:22:31Z", claims, "eidas");

        Map<String,Object> ver = verification(vc);
        assertEquals("eidas", ver.get("trust_framework"));
        assertEquals("2026-08-03T14:22:31Z", ver.get("time"));
        List<Map<String,Object>> evidence = (List<Map<String,Object>>) ver.get("evidence");
        assertEquals(1, evidence.size());
        Map<String,Object> ev = evidence.get(0);
        assertEquals("vc", ev.get("type"));
        assertEquals("oid4vp", ev.get("method"));
        assertEquals("dc+sd-jwt", ev.get("format"));
        assertEquals("urn:eudi:pid:1", ev.get("vct"));
        assertEquals("https://issuer.example", ev.get("issuer"));
        assertEquals("CN=Test CA", ev.get("trust_anchor"));

        Map<String,Object> outClaims = (Map<String,Object>) vc.get("claims");
        assertEquals("Marie", outClaims.get("given_name"));
        assertEquals(Boolean.TRUE, outClaims.get("age_over_18"));
        // metadata does not leak into claims
        assertFalse(outClaims.containsKey("issuer"));
        assertFalse(outClaims.containsKey("vct"));
    }

    @Test
    void omitsNullEvidenceFieldsButKeepsTrustFramework() {
        Map<String,Object> vc = VerifiedClaimsBuilder.build(
            null, null, null, null, null, new LinkedHashMap<>(), "eidas");
        Map<String,Object> ver = verification(vc);
        assertEquals("eidas", ver.get("trust_framework"));
        List<Map<String,Object>> evidence = (List<Map<String,Object>>) ver.get("evidence");
        Map<String,Object> ev = evidence.get(0);
        assertEquals("vc", ev.get("type"));         // type always present
        assertFalse(ev.containsKey("issuer"));       // nulls omitted
        assertFalse(ev.containsKey("vct"));
    }

    @Test
    void omitsTimeKeyWhenVerifiedAtIsNull() {
        Map<String,Object> vc = VerifiedClaimsBuilder.build(
            null, null, null, null, null, new LinkedHashMap<>(), "eidas");
        Map<String,Object> ver = verification(vc);
        // "time" must be absent, not present with a literal null value.
        assertFalse(ver.containsKey("time"));
    }

    @Test
    void oneEntryCollapsesToAnObject() {
        Map<String, Object> single = VerifiedClaimsBuilder.build("iss", "vct", "dc+sd-jwt", "CN=ca",
            "2026-08-06T00:00:00Z", Map.of("sub", "S"), "eidas");

        assertSame(single, VerifiedClaimsBuilder.collapse(List.of(single)),
            "one presentation -> an object, exactly as before: no consumer is broken");
    }

    @Test
    void twoEntriesCollapseToAnArray() {
        Map<String, Object> a = VerifiedClaimsBuilder.build("i1", "urn:eudi:pid:1", "dc+sd-jwt",
            "CN=ca", "T", Map.of("given_name", "Marie"), "eidas");
        Map<String, Object> b = VerifiedClaimsBuilder.build("i2", "urn:pn:account-holder:1",
            "dc+sd-jwt", "CN=ca", "T", Map.of("sub", "FED-1"), "pn_account_possession");

        Object collapsed = VerifiedClaimsBuilder.collapse(List.of(a, b));

        assertTrue(collapsed instanceof List<?>);
        assertEquals(2, ((List<?>) collapsed).size());
        assertEquals("eidas", ((Map<?, ?>) ((Map<?, ?>) ((List<?>) collapsed).get(0))
            .get("verification")).get("trust_framework"));
        assertEquals("pn_account_possession", ((Map<?, ?>) ((Map<?, ?>) ((List<?>) collapsed).get(1))
            .get("verification")).get("trust_framework"),
            "each assertion stays attributed to the card carrying it");
    }

    @Test
    void nothingToSayCollapsesToNull() {
        assertNull(VerifiedClaimsBuilder.collapse(List.of()));
    }
}
