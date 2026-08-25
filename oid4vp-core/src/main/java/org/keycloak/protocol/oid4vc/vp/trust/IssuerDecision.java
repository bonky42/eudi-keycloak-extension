package org.keycloak.protocol.oid4vc.vp.trust;

/**
 * Outcome of asking whether an issuer may sign a given credential type.
 *
 * <p>An enum rather than a boolean, for two values today. Not premature generality: this is the
 * seam a role-aware policy plugs into later, and widening a return type ripples through every
 * caller where adding a constant does not. It also reads better at the decision site than a bare
 * {@code true}.</p>
 */
public enum IssuerDecision {

    /** The issuer is entitled to sign this credential type. */
    ALLOWED,

    /** The issuer chains to a trusted anchor, but not one entitled to sign this type. */
    REFUSED
}
