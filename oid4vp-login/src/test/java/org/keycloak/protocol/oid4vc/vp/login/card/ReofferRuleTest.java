package org.keycloak.protocol.oid4vc.vp.login.card;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReofferRuleTest {

    private static final String OWN = "urn:pn:account-holder:1";
    private static final String PID = "urn:eudi:pid:1";
    private static final long NOW = 1_000_000L;
    private static final int SEUIL = 1000;

    private static boolean offer(List<PresentedCard> presented) {
        return ReofferRule.shouldOffer(presented, OWN, NOW, SEUIL);
    }

    @Test
    void aPidOnlyResponseBootstrapsOrRebootstrapsTheCard() {
        assertTrue(offer(List.of(new PresentedCard(PID, null))),
            "a new holder, or a new or reset phone: either way this DEVICE does not have our "
                + "card, and that is the only thing that matters");
    }

    @Test
    void bothCardsWithAFreshOneOfferNothing() {
        assertFalse(offer(List.of(new PresentedCard(PID, null),
                                  new PresentedCard(OWN, NOW + 10_000))),
            "this device already has everything");
    }

    @Test
    void ourFreshCardAloneOffersNothing() {
        assertFalse(offer(List.of(new PresentedCard(OWN, NOW + 10_000))));
    }

    @Test
    void ourCardCloseToExpiryIsRenewedEvenAlongsideAPid() {
        assertTrue(offer(List.of(new PresentedCard(PID, null),
                                 new PresentedCard(OWN, NOW + 500))));
    }

    @Test
    void ourCardWithoutAKnownExpiryIsRenewed() {
        assertTrue(offer(List.of(new PresentedCard(OWN, null))),
            "sans expiration connue, on ne peut pas garantir que le porteur en aura une valide demain");
    }

    @Test
    void anExpiredCardNeverReachesHereSoOnlyThePidRemains() {
        // The engine already discarded the expired presentation at link 6, so what reaches here is
        // the PID alone — the case, and the only case, that marks a renewal.
        assertTrue(offer(List.of(new PresentedCard(PID, null))));
    }

    @Test
    void noOwnVctConfiguredNeverOffers() {
        assertFalse(ReofferRule.shouldOffer(List.of(new PresentedCard(PID, null)), null, NOW, SEUIL),
            "a realm that issues nothing keeps exactly its previous behaviour");
    }

    @Test
    void anEmptyOrNullListIsHandled() {
        assertTrue(offer(List.of()));
        assertTrue(ReofferRule.shouldOffer(null, OWN, NOW, SEUIL));
    }
}
