package org.keycloak.protocol.oid4vc.vp.verifier;

/**
 * Normalised error codes for the failure to verify a verifiable presentation (VP token), whatever
 * the concrete format (dc+sd-jwt, mdoc, ...).
 */
public enum VpErrorCode {
    PARSING_ERROR,
    UNTRUSTED_ISSUER,
    /** The chain climbs to a KNOWN anchor, which is however not entitled to sign this
     *  {@code vct}. Deliberately distinct from {@link #UNTRUSTED_ISSUER}: "I do not know that
     *  issuer" and "I know it, but not for that type" send the operator to two different places —
     *  their anchors for one, their pinning for the other. */
    ISSUER_NOT_AUTHORIZED,
    INVALID_SIGNATURE,
    DISCLOSURE_MISMATCH,
    INVALID_KEY_BINDING,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_NOT_YET_VALID,
    QUERY_NOT_SATISFIED,
    /** The vp_token carries a key no credential query declares (OID4VP 1.0 section 8.1).
     *  Refused explicitly — never silently truncated or ignored. */
    UNKNOWN_RESPONSE_KEY,
    /** More than one presentation under a single key while `multiple` was not asked for
     *  (section 8.1). */
    TOO_MANY_PRESENTATIONS,
    /** The wallet's response could not be opened: not a JWE, sealed to another key, altered in
     *  flight, or posted in the clear. One code for all four on purpose — from the operator's seat
     *  the diagnosis is the same, and telling them apart would tell an attacker which one it was. */
    RESPONSE_DECRYPTION_FAILED,
    WALLET_ERROR,
    TRANSACTION_NOT_FOUND,
    TRANSACTION_EXPIRED,
    /** The transaction was found in the store but carries no response-encryption key, so a
     *  {@code direct_post.jwt} request object cannot be built for it (e.g. it was created by a
     *  node predating this feature). Distinct from {@link #TRANSACTION_NOT_FOUND}: the
     *  transaction is known and PENDING, not absent — collapsing the two would hide a rollout/data
     *  problem behind an ordinary "the wallet was too slow" 404. */
    TRANSACTION_MISSING_ENCRYPTION_KEY
}
