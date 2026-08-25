package org.keycloak.protocol.oid4vc.vp.login.card;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The calling rule around {@link CardGrant#ensureGranted}: the entitlement is granted only when a
 * card is about to be offered AND issuance is configured. {@link #grantIfOffering} mirrors the
 * wiring {@code Oid4vpIdentityProvider.authenticationFinished} lays down, and is deliberately not
 * shared with production: {@link CardGrant} carries the grant itself, never the choice of when to
 * invoke it.
 *
 * <p>A transient identity provider never reaches this point, so that case is not replayed here:
 * {@code willOffer=false} already covers "we are not going to offer".</p>
 */
class CardGrantTest {

    private static final String CREDENTIAL_CONFIG_ID = "account-holder-card";

    @Test
    void entitlementAlreadyPresentIsIdempotent() {
        RecordingCardGrant grant = new RecordingCardGrant(true);

        boolean armed = grantIfOffering(true, CREDENTIAL_CONFIG_ID, grant);

        assertTrue(armed);
        assertEquals(1, grant.calls, "ensureGranted is called even when the entitlement exists: "
            + "observing idempotence is CardGrant's job, not the caller's");
        assertEquals(0, grant.grantsCreated, "already entitled: no grant may be issued");
    }

    @Test
    void missingEntitlementIsGrantedAndStaysIdempotentOnAFurtherLogin() {
        RecordingCardGrant grant = new RecordingCardGrant(false);

        boolean firstLogin = grantIfOffering(true, CREDENTIAL_CONFIG_ID, grant);
        boolean secondLogin = grantIfOffering(true, CREDENTIAL_CONFIG_ID, grant);

        assertTrue(firstLogin);
        assertTrue(secondLogin);
        assertEquals(2, grant.calls);
        assertEquals(1, grant.grantsCreated, "absent then present: one grant only, never a second "
            + "at the next login");
    }

    @Test
    void missingCredentialConfigIdGrantsNothingAndSkipsTheOffer() {
        RecordingCardGrant grant = new RecordingCardGrant(false);

        boolean armed = grantIfOffering(true, null, grant);

        assertFalse(armed, "half-configured issuance: do not arm an offer that would fail");
        assertEquals(0, grant.calls);
        assertEquals(0, grant.grantsCreated);
    }

    @Test
    void notOfferingGrantsNothing() {
        RecordingCardGrant grant = new RecordingCardGrant(false);

        boolean armed = grantIfOffering(false, CREDENTIAL_CONFIG_ID, grant);

        assertFalse(armed);
        assertEquals(0, grant.calls, "no offer coming, so no grant may be attempted");
    }

    /**
     * The calling rule under test, wired identically in
     * {@code Oid4vpIdentityProvider.authenticationFinished}: after {@code ReofferRule.shouldOffer}
     * and the {@code ownCredentialConfigId == null} guard, before the action notes are set.
     */
    private static boolean grantIfOffering(boolean willOffer, String credentialConfigId, CardGrant grant) {
        if (!willOffer || credentialConfigId == null) {
            return false;
        }
        return grant.ensureGranted(null);
    }

    /** Records calls without depending on Keycloak: {@code user} is never dereferenced. */
    private static final class RecordingCardGrant implements CardGrant {
        private boolean granted;
        int calls = 0;
        int grantsCreated = 0;

        RecordingCardGrant(boolean alreadyGranted) {
            this.granted = alreadyGranted;
        }

        @Override
        public boolean ensureGranted(UserModel user) {
            calls++;
            if (!granted) {
                grantsCreated++;
                granted = true;
            }
            return true;
        }
    }
}
