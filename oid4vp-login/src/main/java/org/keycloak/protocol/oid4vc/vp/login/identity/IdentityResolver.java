package org.keycloak.protocol.oid4vc.vp.login.identity;

import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.List;

/**
 * "Given these verified presentations, what is the federated identifier?"
 *
 * <p>Deliberately reduced to that one question, so it stays substitutable: today's implementation
 * reads a {@code vct -> subject claim} table; the device-management one will query the credential's
 * registration instead, which settles pinning at the same time, a forged card then matching no
 * registration.</p>
 *
 * <p>A pure function, with no state and no session: callable as is from a future flow
 * {@code ConditionalAuthenticator}.</p>
 *
 * <p><b>Ambiguity is refused, never resolved by ordering.</b> When several presentations could
 * equally found the identity and no precedence rule separates them, an implementation MUST return
 * {@code null} rather than take the first in the list — that order is the {@code vp_token}'s,
 * decided by the wallet, and never a signal of identity.</p>
 */
@FunctionalInterface
public interface IdentityResolver {

    /** @return the identity retained, or {@code null} if no presentation carries a stable
     *          subject. */
    ResolvedIdentity resolve(List<VerifiedPresentation> presentations);
}
