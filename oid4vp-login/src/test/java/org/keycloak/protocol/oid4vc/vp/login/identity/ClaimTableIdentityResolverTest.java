package org.keycloak.protocol.oid4vc.vp.login.identity;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ClaimTableIdentityResolverTest {

    private static final String OWN = "urn:pn:account-holder:1";
    private static final String PID = "urn:eudi:pid:1";
    private static final String TABLE = PID + "=sub," + OWN + "=sub";

    private static VerifiedPresentation vp(String vct, Map<String, Object> claims) {
        return new VerifiedPresentation(claims, "https://issuer.example", "CN=ca", vct, null);
    }

    private final IdentityResolver resolver = new ClaimTableIdentityResolver(TABLE, "sub", OWN);

    @Test
    void ourCardFoundsTheIdentityWheneverItIsPresent() {
        ResolvedIdentity identity = resolver.resolve(List.of(
            vp(PID, Map.of("sub", "PID-1")),
            vp(OWN, Map.of("sub", "FED-1"))));

        assertEquals(OWN, identity.source().getVct());
        assertEquals("FED-1", identity.federatedId(),
            "the verbatim regime: WE wrote this value at issuance, and prefixing it again would "
                + "fabricate a federated link different from the first enrolment's");
    }

    @Test
    void thePidFoundsItWhenOurCardIsAbsent() {
        ResolvedIdentity identity = resolver.resolve(List.of(vp(PID, Map.of("sub", "PID-1"))));

        assertEquals(PID, identity.source().getVct());
        assertEquals("https://issuer.example:PID-1", identity.federatedId(),
            "unchanged for any third-party credential: issuer + ':' + value");
    }

    @Test
    void theTableSaysWhichClaimCarriesTheSubject() {
        IdentityResolver custom = new ClaimTableIdentityResolver(
            PID + "=personal_administrative_number", "sub", OWN);

        assertEquals("https://issuer.example:PAN-9",
            custom.resolve(List.of(vp(PID, Map.of("personal_administrative_number", "PAN-9",
                "sub", "IGNORÉ")))).federatedId());
    }

    @Test
    void aVctAbsentFromTheTableFallsBackToTheGlobalSubjectClaim() {
        IdentityResolver custom = new ClaimTableIdentityResolver(OWN + "=sub", "sub", OWN);

        assertEquals("https://issuer.example:PID-1",
            custom.resolve(List.of(vp(PID, Map.of("sub", "PID-1")))).federatedId(),
            "older realms must keep working with no table at all");
    }

    @Test
    void noStableSubjectResolvesToNull() {
        assertNull(resolver.resolve(List.of(vp(PID, Map.of("given_name", "Marie")))));
        assertNull(resolver.resolve(List.of()));
    }

    @Test
    void ourCardWithoutSubjectDoesNotFallBackOntoThePid() {
        // Fail closed: our card is present, so it decides — and if it carries no subject that is a
        // refusal, not an occasion to fall back onto another identity.
        assertNull(resolver.resolve(List.of(
            vp(PID, Map.of("sub", "PID-1")),
            vp(OWN, Map.of("given_name", "Marie")))));
    }

    /**
     * Without our card, two third-party presentations each carrying a usable subject are
     * irreducibly ambiguous: {@code dcqlQueryJson} is free-form administrator text and may well
     * declare a second PID, and taking the first in the list would let the wallet's chosen order
     * name the account.
     */
    @Test
    void twoNonOwnPresentationsWithAUsableSubjectAreRefusedAsAmbiguous() {
        String secondPid = "urn:eudi:pid:2";
        IdentityResolver custom = new ClaimTableIdentityResolver(
            TABLE + "," + secondPid + "=sub", "sub", OWN);

        assertNull(custom.resolve(List.of(
            vp(PID, Map.of("sub", "PID-1")),
            vp(secondPid, Map.of("sub", "PID-2")))),
            "two presentations other than our card each carry a subject: no precedence rule "
                + "separates them, so refuse rather than guess from the wallet's order");
    }

    /**
     * A PID accompanied by a presentation with NO subject is not ambiguous: only one presentation
     * carries a subject, so it wins whatever its position in the list.
     */
    @Test
    void oneSubjectBearingPresentationPlusOneWithoutASubjectStillResolves() {
        ResolvedIdentity identity = resolver.resolve(List.of(
            vp(PID, Map.of("given_name", "Marie")),   // pas de "sub" : aucun sujet exploitable
            vp("urn:eudi:pid:2", Map.of("sub", "PID-2"))));

        assertEquals("urn:eudi:pid:2", identity.source().getVct());
        assertEquals("https://issuer.example:PID-2", identity.federatedId());
    }
}
