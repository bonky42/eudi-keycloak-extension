package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the rule that decides which cards the page and the tab offer.
 *
 * <p>The list is <b>derived from the realm</b>, never hard-coded: adding a format is done by
 * creating a credential scope in Keycloak, and it shows up. That property is what makes "we will
 * offer different formats" true without coming back to the code every time — so that is what needs
 * protecting, not today's list.</p>
 *
 * <p><b>The protocol is the only reliable discriminator.</b> Observed in production on 2026-08-16:
 * filtering on the presence of a configuration id rejects NOTHING, because
 * {@code CredentialScopeModel.getCredentialConfigurationId()} falls back to the scope name when the
 * attribute is absent. The JSON endpoint was therefore advertising `acr`, `address`, `email`,
 * `profile` and `roles` as requestable cards. A realm has a dozen or so stock scopes: without this
 * filter the list is unreadable and every button leads to a failure.</p>
 */
class OfferableCardsTest {

    private static final String CARD = "oid4vc";
    private static final String OIDC = "openid-connect";

    @Test
    void onlyOid4vcScopesAreCards() {
        List<OfferableCard> cards = OfferableCards.from(List.of(
            new ScopeCandidate("profile", OIDC, "profile"),
            new ScopeCandidate("email", OIDC, "email"),
            new ScopeCandidate("eudi-pid", CARD, "eudi-pid")));

        assertEquals(1, cards.size(), "a realm's stock scopes are not cards, even though they do "
            + "expose a configuration id");
        assertEquals("eudi-pid", cards.get(0).configurationId());
    }

    @Test
    void scopesCarryingAConfigurationIdAreOffered() {
        List<OfferableCard> cards = OfferableCards.from(List.of(
            new ScopeCandidate("account-holder", CARD, "account-holder-card"),
            new ScopeCandidate("eudi-pid", CARD, "eudi-pid")));

        assertEquals(2, cards.size());
        assertEquals("account-holder", cards.get(0).displayName());
        assertEquals("account-holder-card", cards.get(0).configurationId());
    }

    @Test
    void scopeWithoutConfigurationIdIsOmittedRatherThanShownBroken() {
        List<OfferableCard> cards = OfferableCards.from(List.of(
            new ScopeCandidate("half-configured", CARD, null),
            new ScopeCandidate("blank", CARD, "  "),
            new ScopeCandidate("eudi-pid", CARD, "eudi-pid")));

        assertEquals(1, cards.size(), "only cards that can actually be requested are offered");
        assertEquals("eudi-pid", cards.get(0).configurationId());
    }

    @Test
    void orderIsStableSoTheListDoesNotShuffleBetweenTwoVisits() {
        List<ScopeCandidate> input = List.of(
            new ScopeCandidate("zeta", CARD, "z"),
            new ScopeCandidate("alpha", CARD, "a"),
            new ScopeCandidate("mu", CARD, "m"));

        List<String> names = OfferableCards.from(input).stream().map(OfferableCard::displayName).toList();

        assertEquals(List.of("alpha", "mu", "zeta"), names,
            "a realm's scope order is not guaranteed; without sorting the buttons would move "
                + "between two visits");
    }

    @Test
    void anEmptyRealmYieldsAnEmptyCatalogueNotAnError() {
        assertTrue(OfferableCards.from(List.of()).isEmpty());
    }
}
