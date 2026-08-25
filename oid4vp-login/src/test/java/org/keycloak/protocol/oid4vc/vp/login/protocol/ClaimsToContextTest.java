package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ClaimsToContextTest {

    private static final String OWN = "urn:pn:account-holder:1";
    private static final String PID = "urn:eudi:pid:1";

    private static VerifiedPresentation vp(String vct, Map<String, Object> claims) {
        return new VerifiedPresentation(claims, "https://issuer.example", "CN=ca", vct, null);
    }

    @Test
    void thePidWinsOnCollidingProfileClaims() {
        // The identity comes from our card, but the PID is the source of the identity checks: our
        // card has no authority to contradict a verified civil status.
        Map<String, Object> merged = ClaimsToContext.mergedClaims(List.of(
            vp(OWN, Map.of("sub", "FED-1", "given_name", "Ancienne")),
            vp(PID, Map.of("given_name", "Marie"))), OWN);

        assertEquals("Marie", merged.get("given_name"));
        assertEquals("FED-1", merged.get("sub"),
            "a claim only our card carries stays present");
    }

    @Test
    void mergingIsOrderIndependent() {
        Map<String, Object> merged = ClaimsToContext.mergedClaims(List.of(
            vp(PID, Map.of("given_name", "Marie")),
            vp(OWN, Map.of("given_name", "Ancienne"))), OWN);

        assertEquals("Marie", merged.get("given_name"),
            "the TYPE decides precedence, never the order the wallet filed the keys in");
    }

    @Test
    void aSinglePresentationMergesToItsOwnClaims() {
        assertEquals(Map.of("sub", "PID-1"),
            ClaimsToContext.mergedClaims(List.of(vp(PID, Map.of("sub", "PID-1"))), OWN));
    }

    /** {@code ownVct == null} disables the first pass entirely, so the two loops collapse into
     *  one in list order and the LAST element wins — never a privileged "own" card, since there is
     *  none without {@code ownVct}. This is exactly a realm that issues no card. */
    @Test
    void nullOwnVctMakesTheLastPresentationInTheListWin() {
        Map<String, Object> merged = ClaimsToContext.mergedClaims(List.of(
            vp(PID, Map.of("given_name", "Marie")),
            vp(OWN, Map.of("given_name", "Ancienne"))), null);

        assertEquals("Ancienne", merged.get("given_name"));
    }

    @Test
    void applyWithMatchingClaimSetsUsernameEmailAndAttributes() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("family_name", "Curie");
        claims.put("email", "marie@example.org");
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example.org",
                "did:example:trust-anchor", "urn:eu.europa.ec.eudi:pid:1");
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        ClaimsToContext.apply(vp, claims, ctx, "email", "sub");

        assertEquals("marie@example.org", ctx.getUsername());
        assertEquals("marie@example.org", ctx.getEmail());
        // given_name/family_name also feed the standard first/last name profile.
        assertEquals("Marie", ctx.getFirstName());
        assertEquals("Curie", ctx.getLastName());
        assertEquals("Marie", ctx.getUserAttribute("oid4vp.given_name"));
        assertEquals("marie@example.org", ctx.getUserAttribute("oid4vp.email"));
        assertEquals("https://issuer.example.org", ctx.getUserAttribute("oid4vp.issuer"));
        assertEquals("urn:eu.europa.ec.eudi:pid:1", ctx.getUserAttribute("oid4vp.vct"));
    }

    @Test
    void applyWithoutMatchingClaimDerivesUsernameFromIssuerAndSkipsEmail() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("sub", "user-123");
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example.org",
                "did:example:trust-anchor", "urn:eu.europa.ec.eudi:pid:1");
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        ClaimsToContext.apply(vp, claims, ctx, null, "sub");

        assertEquals("https://issuer.example.org:user-123", ctx.getUsername());
        assertNull(ctx.getEmail());
        assertEquals("Marie", ctx.getUserAttribute("oid4vp.given_name"));
        assertEquals("https://issuer.example.org", ctx.getUserAttribute("oid4vp.issuer"));
        assertEquals("urn:eu.europa.ec.eudi:pid:1", ctx.getUserAttribute("oid4vp.vct"));
    }

    @Test
    void applyUsernameFallbackFollowsConfiguredSubjectClaimNotLiteralSub() {
        // subjectClaim="personal_identifier", no "sub" claim, matchingClaim absent from claims:
        // the username fallback must read the CONFIGURED subject claim, not the literal "sub" —
        // otherwise every holder without a "sub" claim collapses onto "issuer:unknown" and
        // collides at first broker login (the bug this fix addresses).
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("personal_identifier", "PID-98765");
        claims.put("given_name", "Marie");
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example.org",
                "did:example:trust-anchor", "urn:eu.europa.ec.eudi:pid:1");
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        ClaimsToContext.apply(vp, claims, ctx, "matching-claim-not-in-claims", "personal_identifier");

        // BrokeredIdentityContext lowercases usernames, hence "pid-98765" not "PID-98765" — the
        // point of this assertion is the claim used, not the casing.
        assertEquals("https://issuer.example.org:pid-98765", ctx.getUsername());
        assertNotEquals("https://issuer.example.org:unknown", ctx.getUsername());
    }

    @Test
    void applyWithNullIssuerAndVctDoesNotThrowNorCreateNullAttributes() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("email", "marie@example.org");
        // issuer, trustAnchorSubject and vct all null (e.g. rebuilt from a transaction lacking them).
        VerifiedPresentation vp = new VerifiedPresentation(claims, null, null, null);
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        assertDoesNotThrow(() -> ClaimsToContext.apply(vp, claims, ctx, "email", "sub"));

        assertEquals("marie@example.org", ctx.getUsername());
        assertEquals("Marie", ctx.getUserAttribute("oid4vp.given_name"));
        // No "null"-valued attributes must be created for the absent issuer/vct.
        assertNull(ctx.getUserAttribute("oid4vp.issuer"));
        assertNull(ctx.getUserAttribute("oid4vp.vct"));
    }

    @Test
    void brokeredIdentityIdUsesTheConfiguredSubjectClaim() {
        java.util.Map<String,Object> claims = new java.util.LinkedHashMap<>();
        claims.put("personal_identifier", "PID-12345");
        claims.put("email", "marie@example.org");
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example", "CN=CA", "urn:eudi:pid:1");
        assertEquals("https://issuer.example:PID-12345",
            ClaimsToContext.brokeredIdentityId(vp, "personal_identifier", null));
    }

    @Test
    void brokeredIdentityIdIsNullWhenSubjectClaimAbsent() {
        java.util.Map<String,Object> claims = new java.util.LinkedHashMap<>();
        claims.put("given_name", "Marie");
        claims.put("email", "marie@example.org");
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example", "CN=CA", "urn:eudi:pid:1");
        assertNull(ClaimsToContext.brokeredIdentityId(vp, "sub", null));
    }

    @Test
    void matchingClaimNoLongerInfluencesTheIdentityId() {
        // Two presentations, same subject, different matchingClaim (email) -> SAME identifier.
        java.util.Map<String,Object> a = new java.util.LinkedHashMap<>();
        a.put("sub", "S-1"); a.put("email", "old@example.org");
        java.util.Map<String,Object> b = new java.util.LinkedHashMap<>();
        b.put("sub", "S-1"); b.put("email", "new@example.org");
        VerifiedPresentation vpA = new VerifiedPresentation(a, "https://issuer.example", "CN=CA", "urn:eudi:pid:1");
        VerifiedPresentation vpB = new VerifiedPresentation(b, "https://issuer.example", "CN=CA", "urn:eudi:pid:1");
        assertEquals(ClaimsToContext.brokeredIdentityId(vpA, "sub", null),
                     ClaimsToContext.brokeredIdentityId(vpB, "sub", null));
    }

    @Test
    void noIdentifierIsEverDerivedFromClaimContent() {
        // Preuve que le hash a disparu : sans sujet, aucune valeur n'est produite,
        // quel que soit le contenu des claims.
        java.util.Map<String,Object> claims = new java.util.LinkedHashMap<>();
        claims.put("given_name", "Marie"); claims.put("age_over_18", true);
        VerifiedPresentation vp = new VerifiedPresentation(claims, "https://issuer.example", "CN=CA", "urn:eudi:pid:1");
        assertNull(ClaimsToContext.brokeredIdentityId(vp, "sub", null));
        assertNull(ClaimsToContext.brokeredIdentityId(vp, "personal_identifier", null));
    }

    @Test
    void ownVctSubjectIsTakenVerbatimWithoutIssuerPrefix() {
        VerifiedPresentation vp = new VerifiedPresentation(
            Map.of("sub", "https://test-issuer.example.org:PID-1"),
            "https://kc.example/realms/oid4vp-test", "CN=ca", "urn:pn:account-holder:1", null);

        assertEquals("https://test-issuer.example.org:PID-1",
            ClaimsToContext.brokeredIdentityId(vp, "sub", "urn:pn:account-holder:1"),
            "our card CARRIES the federated identity: prefixing it with our issuer would create a "
                + "second federated link and restart a first-broker-login");
    }

    @Test
    void otherVctKeepsTheIssuerPrefixedRule() {
        VerifiedPresentation vp = new VerifiedPresentation(
            Map.of("sub", "PID-1"), "https://test-issuer.example.org", "CN=ca", "urn:eudi:pid:1", null);

        assertEquals("https://test-issuer.example.org:PID-1",
            ClaimsToContext.brokeredIdentityId(vp, "sub", "urn:pn:account-holder:1"));
    }

    @Test
    void ownVctWithBlankSubjectIsStillRefused() {
        VerifiedPresentation vp = new VerifiedPresentation(
            Map.of("sub", "  "), "https://kc.example", "CN=ca", "urn:pn:account-holder:1", null);

        assertNull(ClaimsToContext.brokeredIdentityId(vp, "sub", "urn:pn:account-holder:1"));
    }

    @Test
    void nullOwnVctDisablesVerbatimEntirely() {
        VerifiedPresentation vp = new VerifiedPresentation(
            Map.of("sub", "S"), "https://kc.example", "CN=ca", "urn:pn:account-holder:1", null);

        assertEquals("https://kc.example:S", ClaimsToContext.brokeredIdentityId(vp, "sub", null));
    }

    @Test
    void applyFederatedIdSetsAttributeWhenStableSubjectIdPresent() {
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        ClaimsToContext.applyFederatedId(ctx, "https://issuer.example:PID-1");

        assertEquals("https://issuer.example:PID-1", ctx.getUserAttribute(ClaimsToContext.FEDID_ATTRIBUTE));
    }

    @Test
    void applyFederatedIdSetsNoAttributeWhenNoStableSubjectId() {
        // The transient path must pass null here, never the random fallback identifier. This is
        // what proves oid4vp.fedid can never carry a computed value.
        BrokeredIdentityContext ctx = new BrokeredIdentityContext("id", enabledIdpModel());

        ClaimsToContext.applyFederatedId(ctx, null);

        assertNull(ctx.getUserAttribute(ClaimsToContext.FEDID_ATTRIBUTE));
    }

    private static IdentityProviderModel enabledIdpModel() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setEnabled(true);
        return model;
    }
}
