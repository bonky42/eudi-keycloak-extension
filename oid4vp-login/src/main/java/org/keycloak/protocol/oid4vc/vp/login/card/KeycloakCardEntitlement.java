package org.keycloak.protocol.oid4vc.vp.login.card;

import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;

import org.jboss.logging.Logger;

/**
 * The entitlement is the {@code UserVerifiableCredentialModel} attached to our card's credential
 * scope. An administrator revokes it with
 * {@code DELETE /admin/realms/{realm}/users/{id}/vc/credentials/{credentialScopeName}}, which cuts
 * ALL cards of that type for that holder at once — revocation in bulk, for want of any way to name
 * one device: the native model carries no label.
 *
 * <p>Four paths lead to {@code false} and only one is a revocation proper (the last {@code return}
 * below). The other three are lock-out modes caused by configuration or account state — most
 * likely {@code ownCredentialConfigId} pointing at a credential scope's name instead of its
 * {@code vc.credential_configuration_id} attribute, which would block EVERY holder indefinitely.
 * Each branch therefore logs its own exact cause BEFORE returning, so an operator never reads
 * "revoked" where the truth is "I cannot evaluate the entitlement".</p>
 */
public final class KeycloakCardEntitlement implements CardEntitlement {

    private static final Logger LOG = Logger.getLogger(KeycloakCardEntitlement.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final String identityProviderAlias;
    private final String credentialConfigId;

    public KeycloakCardEntitlement(KeycloakSession session, RealmModel realm,
                                    String identityProviderAlias, String credentialConfigId) {
        this.session = session;
        this.realm = realm;
        this.identityProviderAlias = identityProviderAlias;
        this.credentialConfigId = credentialConfigId;
    }

    @Override
    public boolean isEntitled(String federatedId) {
        if (credentialConfigId == null) {
            // Issuance is half-configured, so the entitlement cannot be proved and is refused.
            // NOT a revocation: the identity provider never knew which scope to ask about.
            LOG.warnf("Card entitlement check for federated id %s: ownCredentialConfigId is not "
                + "configured; issuance/re-authentication for this vct is only half-configured, refusing",
                federatedId);
            return false;
        }
        if (federatedId == null || federatedId.isBlank()) {
            // Defensive: cardAccepted() already guards this on the pure-decision side, but this
            // class is public and a future caller could reach it directly.
            LOG.warnf("Card entitlement check called with a blank federated id; refusing");
            return false;
        }
        UserModel user = session.users().getUserByFederatedIdentity(realm,
            new FederatedIdentityModel(identityProviderAlias, federatedId, null));
        if (user == null) {
            // No account behind that identifier. Account creation stays governed by
            // first-broker-login, never by this check. NOT a revocation: there was never an
            // account to revoke.
            LOG.warnf("Card entitlement check for federated id %s: no account linked via identity "
                + "provider '%s'; refusing", federatedId, identityProviderAlias);
            return false;
        }
        // Our card's credential scope, found by configuration id (the
        // vc.credential_configuration_id attribute) rather than by name: that is what
        // Oid4vpConfig.ownCredentialConfigId() carries, and the same key the wallet receives in the
        // issuance metadata. null when no scope matches — fail closed, but NOT a revocation: it is
        // a configuration naming no existing credential scope. The likeliest trap is pasting the
        // scope NAME here, the one the DELETE .../vc/credentials/{credentialScopeName} admin
        // endpoint expects, instead of the attribute. Resolution is shared with KeycloakCardGrant
        // on purpose: reading and granting the entitlement must never take different paths.
        CredentialScopeModel scope = OwnCardCredentialScope.resolve(realm, credentialConfigId);
        if (scope == null) {
            LOG.warnf("Card entitlement check for federated id %s: no credential scope in realm '%s' "
                + "has vc.credential_configuration_id '%s' (is ownCredentialConfigId set to a scope "
                + "NAME instead of its credential_configuration_id attribute?); refusing",
                federatedId, realm.getName(), credentialConfigId);
            return false;
        }
        // The native entitlement: one UserVerifiableCredentialModel row for this account and this
        // credential scope. Its presence already governs issuance; here it also governs
        // re-authentication by the card already issued. This is the only branch whose false is a
        // REAL revocation.
        boolean entitled = session.users().getVerifiableCredentialByClientScope(user.getId(), scope.getId()) != null;
        if (!entitled) {
            LOG.warnf("Card entitlement check for federated id %s: no UserVerifiableCredential for "
                + "credential scope '%s' (configuration id '%s') — entitlement revoked or never granted",
                federatedId, scope.getName(), credentialConfigId);
        }
        return entitled;
    }
}
