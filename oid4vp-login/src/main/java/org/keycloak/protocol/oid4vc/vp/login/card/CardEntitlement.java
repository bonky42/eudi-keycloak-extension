package org.keycloak.protocol.oid4vc.vp.login.card;

/**
 * The source of truth on a holder's entitlement to the card THIS Keycloak issues.
 *
 * <p>Deliberately reduced to one question — "is this holder still entitled?" — so the
 * implementation stays substitutable. Today it answers from the native entitlement
 * ({@code UserVerifiableCredentialModel}), revoked in bulk by an administrator; a later
 * implementation will answer from a credential provider of our own, where the holder deletes the
 * lost device themselves. Per-card control is out of reach in Keycloak 26.7: a card's {@code jti}
 * and the issued-card registry's identifier are unrelated.</p>
 */
@FunctionalInterface
public interface CardEntitlement {

    boolean isEntitled(String federatedId);

    /**
     * Decides whether a presentation may authenticate, on the entitlement question alone.
     *
     * <p>Fail closed: a presentation of OUR type with no federated identifier, or whose holder is
     * no longer entitled, is refused. Credentials from another issuer are out of scope — their
     * revocation belongs to CRL/OCSP — and an unconfigured {@code ownVct} disables the check
     * entirely, so a realm that issues nothing is unaffected.</p>
     */
    static boolean cardAccepted(String vct, String ownVct, String federatedId, CardEntitlement entitlement) {
        if (ownVct == null || !ownVct.equals(vct)) {
            return true;
        }
        if (federatedId == null || federatedId.isBlank()) {
            return false;
        }
        return entitlement.isEntitled(federatedId);
    }
}
