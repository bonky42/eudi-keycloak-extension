package org.keycloak.protocol.oid4vc.vp.login.card;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Covers only the {@link KeycloakCardEntitlement} branches that refuse BEFORE dereferencing
 * {@code session} or {@code realm}, and are therefore testable without mocking the Keycloak model.
 * The rest — resolving the account, the credential scope and the native entitlement — needs a real
 * Keycloak and is covered end to end.
 */
class KeycloakCardEntitlementTest {

    @Test
    void halfConfiguredIssuanceRefusesWithoutDereferencingAnything() {
        // With credentialConfigId absent the check refuses on its first line, before touching
        // session or realm. A future reordering that reached the model first would crash here with
        // an NPE rather than silently accept.
        CardEntitlement entitlement = new KeycloakCardEntitlement(null, null, null, null);
        assertFalse(entitlement.isEntitled("https://iss:ALICE"));
    }

    @Test
    void blankFederatedIdIsRefusedEvenWhenCalledDirectly() {
        // cardAccepted() already guards this, but KeycloakCardEntitlement is public and a future
        // caller could reach it directly, bypassing that guard.
        CardEntitlement entitlement = new KeycloakCardEntitlement(null, null, null, "account-holder-card");
        assertFalse(entitlement.isEntitled("   "));
        assertFalse(entitlement.isEntitled(null));
    }
}
