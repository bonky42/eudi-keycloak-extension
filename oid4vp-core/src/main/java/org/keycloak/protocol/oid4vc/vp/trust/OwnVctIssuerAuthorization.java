package org.keycloak.protocol.oid4vc.vp.trust;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The only rule in force today: a credential claiming the {@code vct} this Keycloak issues itself
 * must have been signed under the anchor designated as ours.
 *
 * <p>Without it, any issuer chaining to any configured trust anchor could mint a credential of our
 * type carrying an arbitrary subject — and for that type the subject becomes the federated identity
 * <em>verbatim</em>, with no issuer prefix (see {@code ClaimsToContext#brokeredIdentityId}). That is
 * account impersonation, not an information leak.</p>
 *
 * <p>The verbatim regime is itself correct: we wrote that subject ourselves at issuance, from the
 * account's already-established identifier, and prefixing it a second time would fabricate a
 * different federated link and restart a first-broker-login. The regime is not the defect — granting
 * it on the strength of a self-declared type string is.</p>
 *
 * <p>The rule is <b>one-directional</b>. It constrains who may sign our type; it does not constrain
 * what our anchor may sign. The converse would add nothing: abusing it already requires control of
 * our issuing key.</p>
 *
 * <p>Several anchors are accepted, not one, and that is deliberate. Pinning a single anchor would
 * reproduce on a longer timescale the very defect that ruled out pinning the leaf certificate:
 * rotating the issuing authority would invalidate every card in circulation at once. A set lets the
 * outgoing and incoming authorities overlap.</p>
 */
public final class OwnVctIssuerAuthorization implements IssuerAuthorization {

    private final String ownVct;
    private final List<X509Certificate> pinnedAnchors;

    /**
     * @param ownVct        the credential type this Keycloak issues, or {@code null}/blank when
     *                      issuance is not configured — in which case nothing is ever constrained
     * @param pinnedAnchors the anchors entitled to sign {@code ownVct}. Empty means unconfigured,
     *                      and unconfigured <b>refuses</b>: issuance without pinning must be a
     *                      visible outage, not a hole that opens later on the day a third-party
     *                      anchor is added and nobody connects the two events
     */
    public OwnVctIssuerAuthorization(String ownVct, List<X509Certificate> pinnedAnchors) {
        this.ownVct = ownVct == null || ownVct.isBlank() ? null : ownVct;
        this.pinnedAnchors = pinnedAnchors == null ? List.of() : List.copyOf(pinnedAnchors);
    }

    @Override
    public IssuerDecision decide(String vct, X509Certificate validatingAnchor) {
        if (ownVct == null || !ownVct.equals(vct)) {
            return IssuerDecision.ALLOWED;
        }
        return pinnedAnchors.contains(validatingAnchor)
            ? IssuerDecision.ALLOWED
            : IssuerDecision.REFUSED;
    }
}
