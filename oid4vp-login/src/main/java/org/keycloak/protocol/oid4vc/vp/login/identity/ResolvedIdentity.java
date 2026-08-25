package org.keycloak.protocol.oid4vc.vp.login.identity;

import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

/**
 * The identity retained for a login: the federated identifier, and the presentation founding it.
 *
 * <p>The source presentation is exposed because what follows depends on it: its {@code vct} decides
 * whether the entitlement check applies, and its metadata describe the verification in the token.
 * </p>
 */
public record ResolvedIdentity(VerifiedPresentation source, String federatedId) {
}
