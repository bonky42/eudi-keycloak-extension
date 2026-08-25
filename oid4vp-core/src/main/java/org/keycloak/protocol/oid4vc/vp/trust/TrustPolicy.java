package org.keycloak.protocol.oid4vc.vp.trust;

/**
 * The two halves of issuer trust, carried together: which anchors are accepted, and what each of
 * them is entitled to sign.
 *
 * <p>They travel as one object rather than as two parameters because the realm anchor-source
 * components planned for a later phase produce both from the same configuration. Threading them
 * separately would mean wiring that source twice, in two places that must agree.</p>
 */
public final class TrustPolicy {

    private final TrustStore anchors;
    private final IssuerAuthorization authorization;

    public TrustPolicy(TrustStore anchors, IssuerAuthorization authorization) {
        this.anchors = anchors;
        this.authorization = authorization;
    }

    /**
     * A policy that constrains nothing beyond chain validation.
     *
     * <p>For callers with no issuance configured, and for tests whose subject is something else
     * entirely. Named rather than defaulted: "no authorization rule" should be something a reader
     * sees at the call site, not something they have to notice is missing.</p>
     */
    public static TrustPolicy acceptingAll(TrustStore anchors) {
        return new TrustPolicy(anchors, (vct, anchor) -> IssuerDecision.ALLOWED);
    }

    public TrustStore getAnchors() {
        return anchors;
    }

    public IssuerAuthorization getAuthorization() {
        return authorization;
    }
}
