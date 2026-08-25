package org.keycloak.protocol.oid4vc.vp.login.catalog;

import java.util.Comparator;
import java.util.List;

/**
 * Keeps, among a realm's client scopes, those that actually denote a card.
 *
 * <p>Deliberately separated from any Keycloak model traversal: the RULE is what deserves to be
 * pinned by tests, not the walk over the realm. The glue that reads the scopes sits above and can
 * be replaced without touching this.</p>
 */
public final class OfferableCards {

    /** The protocol Keycloak sets on a credential scope. */
    private static final String CARD_PROTOCOL = "oid4vc";

    private OfferableCards() {
    }

    public static List<OfferableCard> from(List<ScopeCandidate> candidates) {
        return candidates.stream()
            // The protocol is the only reliable discriminator. Filtering on the presence of a
            // configuration id rejects nothing: getCredentialConfigurationId() falls back to the
            // scope name when the attribute is missing, so `acr`, `email` and `profile` all passed
            // as requestable cards (observed in production on 2026-08-16).
            .filter(scope -> CARD_PROTOCOL.equals(scope.protocol()))
            // Still useful: a half-configured credential scope cannot be requested, as
            // CardOfferParameter would refuse to build its parameter. Showing a button we already
            // know will fail is worse than showing nothing.
            .filter(scope -> scope.configurationId() != null && !scope.configurationId().isBlank())
            .map(scope -> new OfferableCard(scope.name(), scope.configurationId()))
            // A realm's scope order is not guaranteed; without sorting, the buttons would move
            // between two visits.
            .sorted(Comparator.comparing(OfferableCard::displayName))
            .toList();
    }
}
