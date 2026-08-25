package org.keycloak.protocol.oid4vc.vp.trust;

import java.security.cert.X509Certificate;

/**
 * Decides whether the issuer that signed a credential may issue that credential type.
 *
 * <p>Distinct from {@link TrustStore}, and the distinction is the whole point: {@code TrustStore}
 * answers "does this chain lead to something I trust", this answers "and is that thing entitled to
 * sign <em>this</em>". A trust list — however well maintained — can only ever answer the first
 * question. It says "these issuers are legitimate participants"; it never says "and any of them may
 * issue this particular credential type".</p>
 *
 * <p>Note that OpenID4VP 1.0 lets a Credential Query carry {@code trusted_authorities}, which
 * expresses the same constraint towards the Wallet. That is not a substitute for this interface:
 * the specification states that "Verifiers must verify that the issuer of a received presentation
 * is trusted on their own and this feature mainly aims to help data minimization". A request
 * parameter constrains a cooperating Wallet; it does not constrain whoever posts to the response
 * endpoint.</p>
 *
 * <p>This is the seam a role-aware policy plugs into later: the same call would then express
 * "{@code urn:eudi:pid:1} requires an anchor bearing the PID Provider role", sourced from a trusted
 * list rather than from one pinned certificate.</p>
 */
public interface IssuerAuthorization {

    /**
     * @param vct              credential type carried by the presentation; may be {@code null} when
     *                         the credential declares none
     * @param validatingAnchor the anchor {@link TrustStore#validateChain} terminated at
     * @return the decision; never {@code null}
     */
    IssuerDecision decide(String vct, X509Certificate validatingAnchor);
}
