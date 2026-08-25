package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PresentationNoteTest {

    @Test
    void roundTripsTwoPresentations() {
        List<PresentationNote> notes = List.of(
            new PresentationNote("https://pid.example", "urn:eudi:pid:1", "dc+sd-jwt", "CN=ca",
                "2026-08-06T00:00:00Z", Map.of("given_name", "Marie")),
            new PresentationNote("https://kc.example", "urn:pn:account-holder:1", "dc+sd-jwt",
                "CN=ca", "2026-08-06T00:00:00Z", Map.of("sub", "FED-1")));

        List<PresentationNote> back = PresentationNote.fromJson(PresentationNote.toJson(notes));

        assertEquals(2, back.size());
        assertEquals("urn:eudi:pid:1", back.get(0).vct());
        assertEquals("FED-1", back.get(1).claims().get("sub"));
    }

    @Test
    void unreadableOrEmptyInputYieldsAnEmptyList() {
        assertTrue(PresentationNote.fromJson(null).isEmpty());
        assertTrue(PresentationNote.fromJson("").isEmpty());
        assertTrue(PresentationNote.fromJson("{pas du json").isEmpty(),
            "an unreadable note must not cost the token: the mapper simply emits nothing");
    }

    @Test
    void aNullElementInTheArrayIsDroppedRatherThanThrowing() {
        // Jackson deserialises [null,{...}] into a List with a null element WITHOUT throwing.
        // Filtering here protects every consumer, not just today's mapper, from an NPE that would
        // kill issuance of the whole token instead of omitting one entry.
        String json = "[null,{\"issuer\":\"https://pid.example\",\"vct\":\"urn:eudi:pid:1\","
            + "\"format\":\"dc+sd-jwt\",\"trustAnchor\":\"CN=ca\",\"verifiedAt\":\"T\","
            + "\"claims\":{\"given_name\":\"Marie\"}}]";

        List<PresentationNote> notes = PresentationNote.fromJson(json);

        assertEquals(1, notes.size());
        assertEquals("urn:eudi:pid:1", notes.get(0).vct());
    }
}
