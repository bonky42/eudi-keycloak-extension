package org.keycloak.protocol.oid4vc.vp.login.card;

import org.keycloak.models.UserModel;

/**
 * Grants the holder the entitlement to obtain our card, when needed. Idempotent: if the entitlement
 * already exists, {@link #ensureGranted} merely observes it and never creates a duplicate.
 *
 * <p>Deliberately reduced to one question, mirroring {@link CardEntitlement} on the reading side,
 * so callers stay testable without Keycloak. This interface carries the grant ONLY: deciding WHEN
 * to invoke it — only when about to offer a card, never for a transient identity provider, never
 * without {@code ownCredentialConfigId} — belongs to the caller. {@code CardGrantTest} holds the
 * exact rule.</p>
 */
@FunctionalInterface
public interface CardGrant {

    /** @return true if the entitlement exists, already present or just created; false if granting
     *          is impossible. */
    boolean ensureGranted(UserModel user);
}
