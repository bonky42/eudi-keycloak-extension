package org.keycloak.protocol.oid4vc.vp.login.card;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CardEntitlementTest {

    private static final String OWN = "urn:pn:account-holder:1";
    /** Only this holder is still entitled. */
    private static final CardEntitlement ONLY_ALICE = fedId -> "https://iss:ALICE".equals(fedId);

    @Test
    void aCardOfAnotherTypeIsNotSubjectToThisControl() {
        assertTrue(CardEntitlement.cardAccepted("urn:eudi:pid:1", OWN, "https://iss:BOB", ONLY_ALICE),
            "the check applies to OUR cards only: revoking a PID is its issuer's business");
    }

    @Test
    void ourCardIsAcceptedWhileTheHolderKeepsTheEntitlement() {
        assertTrue(CardEntitlement.cardAccepted(OWN, OWN, "https://iss:ALICE", ONLY_ALICE));
    }

    @Test
    void ourCardIsRefusedOnceTheEntitlementIsRevoked() {
        assertFalse(CardEntitlement.cardAccepted(OWN, OWN, "https://iss:BOB", ONLY_ALICE),
            "revoked: the card stays cryptographically valid, the identity layer is what refuses");
    }

    @Test
    void ourCardWithoutFederatedIdIsRefused() {
        assertFalse(CardEntitlement.cardAccepted(OWN, OWN, null, ONLY_ALICE),
            "fail-closed : sans identifiant, on ne peut pas prouver que le droit existe encore");
    }

    @Test
    void noOwnVctConfiguredDisablesTheControl() {
        assertTrue(CardEntitlement.cardAccepted(OWN, null, null, ONLY_ALICE));
    }
}
