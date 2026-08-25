package org.keycloak.protocol.oid4vc.vp.login.protocol;

import java.util.List;

/**
 * Session note constants for verified claims exchange between IdP and mapper.
 * These note names are shared between the IdP (writer) and mapper (reader).
 */
public final class VerifiedClaimsNotes {
    public static final String ISSUER       = "oid4vp.vc.issuer";
    public static final String VCT          = "oid4vp.vc.vct";
    public static final String FORMAT       = "oid4vp.vc.format";
    public static final String TRUST_ANCHOR = "oid4vp.vc.trustAnchor";
    public static final String VERIFIED_AT  = "oid4vp.vc.verifiedAt";

    /** Every verified presentation of the login, as JSON — see {@link PresentationNote}. It
     *  replaces the older {@code oid4vp.vc.claims} note, which could describe only one. */
    public static final String PRESENTATIONS = "oid4vp.vc.presentations";

    /** Every note name above, in a stable order — the set the IdP hands over to the user session. */
    public static final List<String> ALL =
        List.of(ISSUER, VCT, FORMAT, TRUST_ANCHOR, VERIFIED_AT, PRESENTATIONS);

    /** Internal transport from the identity provider to {@code authenticationFinished}: the
     *  established federated identifier, so {@code oid4vp.fedid} is set at EVERY login. Never a
     *  session note. */
    public static final String CTX_FEDID = "oid4vp.vc.fedid";

    /** Internal transport from the identity provider to {@code authenticationFinished}: the
     *  presented cards and their expiries, as JSON, for the re-offer decision alone. Never a
     *  session note — a card's expiry has no business in a token. */
    public static final String CTX_CARDS = "oid4vp.vc.cards";

    private VerifiedClaimsNotes() {
        // utility class
    }
}
