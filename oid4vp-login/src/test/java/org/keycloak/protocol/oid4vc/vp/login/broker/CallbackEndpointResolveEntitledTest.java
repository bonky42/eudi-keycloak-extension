package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.keycloak.protocol.oid4vc.vp.login.card.CardEntitlement;
import org.keycloak.protocol.oid4vc.vp.login.identity.ClaimTableIdentityResolver;
import org.keycloak.protocol.oid4vc.vp.login.identity.IdentityResolver;
import org.keycloak.protocol.oid4vc.vp.login.identity.ResolvedIdentity;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code CallbackEndpoint.resolveEntitled} is the pure extraction of the "entitlement revoked on
 * our card: discard that presentation and re-resolve the identity on what remains" loop — a
 * deliberate security relaxation that had, until these tests, been verified by reading alone.
 *
 * <p>{@link CardEntitlement} is a {@code @FunctionalInterface}, so the scenarios below pass lambdas
 * rather than the Keycloak implementation, which is only exercisable end to end.</p>
 */
class CallbackEndpointResolveEntitledTest {

    private static final String OWN = "urn:pn:account-holder:1";
    private static final String PID = "urn:eudi:pid:1";
    private static final String TABLE = PID + "=sub," + OWN + "=sub";
    private static final String TX = "tx-1";

    private static VerifiedPresentation vp(String vct, Map<String, Object> claims) {
        return new VerifiedPresentation(claims, "https://issuer.example", "CN=ca", vct, null);
    }

    /** Our card revoked plus a valid PID: the identity falls back to the PID, and our card is gone
     *  from the survivors. This is the "revoke in bulk, the holder re-bootstraps by presenting
     *  their PID" procedure. */
    @Test
    void revokedOwnCardPlusValidPidFallsBackToThePidAndDropsOurCard() {
        VerifiedPresentation ownVp = vp(OWN, Map.of("sub", "FED-1"));
        VerifiedPresentation pidVp = vp(PID, Map.of("sub", "PID-1"));
        List<VerifiedPresentation> presentations = new ArrayList<>(List.of(pidVp, ownVp));

        IdentityResolver resolver = new ClaimTableIdentityResolver(TABLE, "sub", OWN);
        CardEntitlement entitlement = federatedId -> !"FED-1".equals(federatedId);

        ResolvedIdentity identity = Oid4vpIdentityProvider.CallbackEndpoint.resolveEntitled(
            presentations, resolver, entitlement, OWN, TX);

        assertEquals(PID, identity.source().getVct(),
            "our card is revoked: the identity must fall back to the PID, not be refused");
        assertEquals("https://issuer.example:PID-1", identity.federatedId());
        assertEquals(List.of(pidVp), presentations,
            "the revoked card must be gone from the surviving presentations");
    }

    /** Our card revoked and alone in the response: nothing usable left, so a null identity AND an
     *  empty list — which is what {@code complete()} tells apart from "no stable subject". */
    @Test
    void revokedOwnCardAloneYieldsNullIdentityAndAnEmptySurvivorList() {
        VerifiedPresentation ownVp = vp(OWN, Map.of("sub", "FED-1"));
        List<VerifiedPresentation> presentations = new ArrayList<>(List.of(ownVp));

        IdentityResolver resolver = new ClaimTableIdentityResolver(TABLE, "sub", OWN);
        CardEntitlement entitlement = federatedId -> false; // revoked, whatever the subject

        ResolvedIdentity identity = Oid4vpIdentityProvider.CallbackEndpoint.resolveEntitled(
            presentations, resolver, entitlement, OWN, TX);

        assertNull(identity, "our only card is revoked: nothing usable is left");
        assertTrue(presentations.isEmpty(),
            "the revoked card must have been removed, leaving the list empty");
    }

    /** A resolver returning a presentation foreign to the input list — the termination guard
     *  anticipates the device-management resolver, which may rebuild a
     *  {@code VerifiedPresentation} rather than return the instance it was given. The guard fires:
     *  the identity is refused rather than the loop never ending. */
    @Test
    @Timeout(10)
    // Without this bound, a regression removing the termination guard would make this test RUN
    // forever, freezing the build instead of failing it.
    void aResolverReturningAForeignInstanceTripsTheTerminationGuard() {
        VerifiedPresentation ownVp = vp(OWN, Map.of("sub", "FED-1"));
        VerifiedPresentation foreign = vp(OWN, Map.of("sub", "FED-ETRANGERE"));
        List<VerifiedPresentation> presentations = new ArrayList<>(List.of(ownVp));

        // A deliberately faulty resolver: its result rests on an instance that is NOT an element of
        // the list passed in. VerifiedPresentation has no equals(), so
        // presentations.remove(identity.source()) fails on reference identity.
        IdentityResolver resolver = candidates -> new ResolvedIdentity(foreign, "FED-ETRANGERE");
        CardEntitlement entitlement = federatedId -> false; // to reach the removal branch

        ResolvedIdentity identity = Oid4vpIdentityProvider.CallbackEndpoint.resolveEntitled(
            presentations, resolver, entitlement, OWN, TX);

        assertNull(identity,
            "removal by reference fails on a foreign instance: the termination guard must refuse "
                + "rather than loop forever");
    }
}
