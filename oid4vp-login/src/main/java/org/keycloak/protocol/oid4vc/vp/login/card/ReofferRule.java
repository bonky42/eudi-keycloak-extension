package org.keycloak.protocol.oid4vc.vp.login.card;

import java.util.List;

/**
 * Decides whether to offer a fresh card at the end of a login, reading ONLY the response that just
 * authenticated: no server state, no query.
 *
 * <pre>
 * offer  &lt;=&gt;  ownVct is configured
 *             AND no card of ours in the response is still far from expiry
 * </pre>
 *
 * <p>This phrasing, rather than "the presented vct is not ours", is what tells a new phone apart
 * from a pointless duplicate: a holder who already has our card ON THIS DEVICE presents it and gets
 * no second one; a holder whose phone is new cannot present it and receives one — without ever
 * querying a registry which, being per user rather than per device, would answer "they already have
 * one" in precisely the case that needs serving.</p>
 *
 * <p>An <b>expired</b> card never reaches this rule: the engine discarded it at link 6. Here it is
 * therefore indistinguishable from an absent card, which is exactly the verdict wanted.</p>
 */
public final class ReofferRule {

    private ReofferRule() {
    }

    public static boolean shouldOffer(List<PresentedCard> presented, String ownVct,
                                       long now, int reissueBeforeSeconds) {
        if (ownVct == null) {
            return false;
        }
        if (presented == null) {
            return true;
        }
        for (PresentedCard card : presented) {
            if (!ownVct.equals(card.vct())) {
                continue;
            }
            Long expiresAt = card.expiresAt();
            if (expiresAt != null && expiresAt - now >= reissueBeforeSeconds) {
                return false;   // a card of ours, still far from expiry: nothing to offer
            }
        }
        return true;
    }
}
