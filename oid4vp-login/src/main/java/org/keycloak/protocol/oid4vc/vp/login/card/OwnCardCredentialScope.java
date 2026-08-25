package org.keycloak.protocol.oid4vc.vp.login.card;

import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils;

/**
 * Resolves our own card's credential scope from {@code Oid4vpConfig.ownCredentialConfigId()} — the
 * {@code vc.credential_configuration_id} attribute, not the scope's name. The SINGLE point shared
 * between reading the entitlement ({@link KeycloakCardEntitlement}) and granting it
 * ({@link KeycloakCardGrant}): a divergence between the two would be a silent bug, granting an
 * entitlement on one scope while re-authentication checks another.
 *
 * <p>It checks nothing about {@code credentialConfigId} itself: each caller keeps its own guard and
 * its own log message for that case. This class is the delegation to {@link CredentialScopeUtils},
 * nothing more.</p>
 */
final class OwnCardCredentialScope {

    private OwnCardCredentialScope() {
    }

    static CredentialScopeModel resolve(RealmModel realm, String credentialConfigId) {
        return CredentialScopeUtils.findCredentialScopeModelByConfigurationId(
            realm, realm::getClientScopesStream, credentialConfigId);
    }
}
