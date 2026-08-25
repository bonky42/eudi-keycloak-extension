package org.keycloak.protocol.oid4vc.vp.trust;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The rule that stops a trusted third-party issuer from minting a credential of the type this
 * Keycloak issues itself.
 *
 * <p>Both certificates below stand for <em>trusted</em> anchors here: the subject of these tests is
 * not whether a chain validates — {@code TrustStore} settles that — but whether the anchor it
 * validated against is entitled to sign this particular credential type.</p>
 */
class OwnVctIssuerAuthorizationTest {

    private static final String OWN_VCT = "urn:pn:account-holder:1";
    private static final String PID_VCT = "urn:eudi:pid:1";

    private final TestTrustChain chain = new TestTrustChain();
    private final X509Certificate ours = chain.caCert;
    private final X509Certificate theirs = chain.rogueCaCert;

    @Test
    void ourCredentialSignedUnderOurAnchorIsAllowed() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours));
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(OWN_VCT, ours));
    }

    @Test
    void ourCredentialSignedUnderAnotherAnchorIsRefused() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours));
        assertEquals(IssuerDecision.REFUSED, authorization.decide(OWN_VCT, theirs),
            "a credential of our own vct signed by someone else must never be accepted");
    }

    @Test
    void anyOtherCredentialTypeIsUnaffected() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours));
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(PID_VCT, theirs),
            "the rule is one-directional: it constrains our vct, not our anchor");
    }

    @Test
    void withoutOwnVctNothingIsConstrained() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(null, List.of());
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(OWN_VCT, theirs),
            "recognition-only deployments never reach this rule");
    }

    @Test
    void aBlankOwnVctCountsAsUnset() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization("   ", List.of());
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(OWN_VCT, theirs),
            "an admin console field left empty arrives as blank, not null");
    }

    @Test
    void ownVctWithoutPinningIsRefusedByDefault() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of());
        assertEquals(IssuerDecision.REFUSED, authorization.decide(OWN_VCT, ours),
            "issuance without pinning must be a visible outage, not a dormant hole");
    }

    @Test
    void twoPinnedAnchorsBothPass() {
        // Rotating the issuing authority needs an overlap: cards signed by the outgoing anchor stay
        // valid while the incoming one starts issuing. Pinning a single anchor would break every
        // card in circulation the day of the switch.
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours, theirs));
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(OWN_VCT, ours));
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(OWN_VCT, theirs));
    }

    @Test
    void anAnchorOutsideTheSetIsStillRefused() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours));
        assertEquals(IssuerDecision.REFUSED, authorization.decide(OWN_VCT, theirs));
    }

    @Test
    void aPresentationWithoutAVctIsUnaffected() {
        IssuerAuthorization authorization = new OwnVctIssuerAuthorization(OWN_VCT, List.of(ours));
        assertEquals(IssuerDecision.ALLOWED, authorization.decide(null, theirs),
            "a missing vct cannot equal ours; the query conformance check rejects it later");
    }
}
