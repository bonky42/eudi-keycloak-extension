package org.keycloak.protocol.oid4vc.vp.login.card;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;

import org.jboss.logging.Logger;

/**
 * Grants the native entitlement ({@code UserVerifiableCredentialModel}) attached to our card's
 * credential scope — the same row {@link KeycloakCardEntitlement} reads to decide whether an
 * already issued card is still valid, and the same scope, resolved the same way through
 * {@link OwnCardCredentialScope}.
 *
 * <p>Idempotent by construction: {@link #ensureGranted} checks
 * {@code getVerifiableCredentialByClientScope} before writing anything, so a login that re-arms the
 * offer for an already entitled holder never creates a second entitlement. A race between two
 * concurrent logins by the same holder is covered too: a write failing with
 * {@link ModelDuplicateException} means the other request created it between our read and our
 * write, so it is not a failure and {@code true} is returned.</p>
 *
 * <p>Paths to {@code false}: issuance half-configured, or an unexpected write failure. In every
 * case the caller must log and NOT arm the offer — sending the holder to an offer page that would
 * fail helps nobody.</p>
 */
public final class KeycloakCardGrant implements CardGrant {

    private static final Logger LOG = Logger.getLogger(KeycloakCardGrant.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final String credentialConfigId;

    public KeycloakCardGrant(KeycloakSession session, RealmModel realm, String credentialConfigId) {
        this.session = session;
        this.realm = realm;
        this.credentialConfigId = credentialConfigId;
    }

    @Override
    public boolean ensureGranted(UserModel user) {
        if (credentialConfigId == null) {
            // Half-configured issuance: there is no way to know WHICH credential scope to grant,
            // so this refuses rather than guesses.
            LOG.warnf("Card grant requested but ownCredentialConfigId is not configured; issuance "
                + "is only half-configured, refusing to grant");
            return false;
        }
        if (user == null) {
            // Defensive: this class is public and a future caller could reach it without first
            // checking that an authenticated user is available.
            LOG.warnf("Card grant requested with no user; refusing");
            return false;
        }
        CredentialScopeModel scope = OwnCardCredentialScope.resolve(realm, credentialConfigId);
        if (scope == null) {
            LOG.warnf("Card grant for user %s: no credential scope in realm '%s' has "
                + "vc.credential_configuration_id '%s' (is ownCredentialConfigId set to a scope "
                + "NAME instead of its credential_configuration_id attribute?); refusing to grant",
                user.getId(), realm.getName(), credentialConfigId);
            return false;
        }
        if (session.users().getVerifiableCredentialByClientScope(user.getId(), scope.getId()) != null) {
            // Already entitled, by an earlier login or by an administrator: nothing to create.
            return true;
        }
        try {
            session.users().addVerifiableCredential(user.getId(),
                new UserVerifiableCredentialModel(null, scope.getId()));
            LOG.debugf("Granted card entitlement (credential scope '%s') to user %s",
                scope.getName(), user.getId());
            return true;
        } catch (ModelDuplicateException e) {
            // Two concurrent logins by the same holder: the other request created the entitlement
            // between our read and our write. It exists, so this is not a failure.
            LOG.debugf("Card entitlement (credential scope '%s') for user %s was granted "
                + "concurrently; treating as already granted", scope.getName(), user.getId());
            return true;
        } catch (RuntimeException e) {
            LOG.warnf(e, "Failed to grant card entitlement (credential scope '%s') to user %s",
                scope.getName(), user.getId());
            return false;
        }
    }
}
