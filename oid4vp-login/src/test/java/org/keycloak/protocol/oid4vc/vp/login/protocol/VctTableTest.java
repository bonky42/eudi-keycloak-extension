package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VctTableTest {

    @Test
    void parsesPairsAndTrims() {
        assertEquals(Map.of("urn:eudi:pid:1", "sub", "urn:pn:account-holder:1", "sub"),
            VctTable.parse(" urn:eudi:pid:1 = sub , urn:pn:account-holder:1=sub "));
    }

    @Test
    void skipsUnusablePairs() {
        // A `:` instead of `=`, or an empty value: the pair is ignored, never guessed.
        assertTrue(VctTable.parse("urn:eudi:pid:1:sub").isEmpty());
        assertTrue(VctTable.parse("urn:eudi:pid:1=").isEmpty());
        assertTrue(VctTable.parse("=sub").isEmpty());
    }

    @Test
    void anAbsentTableIsAnEmptyMapNeverNull() {
        assertTrue(VctTable.parse(null).isEmpty());
        assertTrue(VctTable.parse("   ").isEmpty());
    }
}
