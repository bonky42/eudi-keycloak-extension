package org.keycloak.protocol.oid4vc.vp.login.identity;

import org.keycloak.protocol.oid4vc.vp.login.protocol.ClaimsToContext;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.List;

/**
 * <b>Our own card founds the identity whenever it is present, otherwise the PID.</b>
 *
 * <p>No identifiers are merged, so no contradiction is possible: our card carries, by construction,
 * the federated identifier of the first enrolment. And if our card is present but carries no
 * subject, resolution fails — it does NOT fall back to the other presentation: the card that
 * decides the identity also decides its absence.</p>
 *
 * <p>With our card absent, falling back to the first presentation would let the {@code vp_token}
 * insertion order — chosen by the wallet, see {@code VpTokenResponse} — pick the identity. That
 * would be bounded only if the DCQL always declared at most one non-{@code ownVct} query, and
 * {@code dcqlQueryJson} is free-form administrator text that may well declare a third one.
 * Resolution therefore requires that <b>exactly one</b> presentation other than our card carries a
 * usable subject: none or several means refusal, never a guessed identity; exactly one wins
 * whatever its position in the response, so a PID accompanied by a subject-less presentation still
 * succeeds.</p>
 */
public final class ClaimTableIdentityResolver implements IdentityResolver {

    private final String subjectClaimByVct;
    private final String defaultSubjectClaim;
    private final String ownVct;

    public ClaimTableIdentityResolver(String subjectClaimByVct, String defaultSubjectClaim,
                                       String ownVct) {
        this.subjectClaimByVct = subjectClaimByVct;
        this.defaultSubjectClaim = defaultSubjectClaim;
        this.ownVct = ownVct;
    }

    @Override
    public ResolvedIdentity resolve(List<VerifiedPresentation> presentations) {
        if (presentations == null || presentations.isEmpty()) {
            return null;
        }
        if (ownVct != null) {
            for (VerifiedPresentation presentation : presentations) {
                if (ownVct.equals(presentation.getVct())) {
                    return identityFor(presentation);
                }
            }
        }
        // Our card is absent. Falling back to the FIRST presentation would let the wallet's
        // vp_token insertion order choose the identity, so exactly ONE presentation must carry a
        // usable subject: none or several means refusal, never a guess.
        VerifiedPresentation candidate = null;
        for (VerifiedPresentation presentation : presentations) {
            if (hasUsableSubject(presentation)) {
                if (candidate != null) {
                    return null; // ambiguous: more than one presentation carries a subject
                }
                candidate = presentation;
            }
        }
        return candidate == null ? null : identityFor(candidate);
    }

    private ResolvedIdentity identityFor(VerifiedPresentation source) {
        String subjectClaim =
            SubjectClaimTable.claimFor(subjectClaimByVct, source.getVct(), defaultSubjectClaim);
        String federatedId = ClaimsToContext.brokeredIdentityId(source, subjectClaim, ownVct);
        return federatedId == null ? null : new ResolvedIdentity(source, federatedId);
    }

    private boolean hasUsableSubject(VerifiedPresentation presentation) {
        String subjectClaim =
            SubjectClaimTable.claimFor(subjectClaimByVct, presentation.getVct(), defaultSubjectClaim);
        return ClaimsToContext.brokeredIdentityId(presentation, subjectClaim, ownVct) != null;
    }
}
