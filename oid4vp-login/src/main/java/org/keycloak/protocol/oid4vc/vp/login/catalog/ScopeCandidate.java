package org.keycloak.protocol.oid4vc.vp.login.catalog;

/**
 * A realm client scope, as read before deciding whether it denotes a card.
 *
 * <p>Deliberately distinct from {@link OfferableCard}: this one is a CANDIDATE, that one a result.
 * The protocol means nothing to whoever displays the list, yet it is the only reliable way to build
 * it — keeping it out of the output type stops it travelling all the way to the screen.</p>
 *
 * @param name            the scope name
 * @param protocol        the declared protocol; {@code oid4vc} for a card
 * @param configurationId whatever {@code getCredentialConfigurationId()} returns — beware, that
 *                        method falls back to the scope NAME when the attribute is absent, so its
 *                        presence proves nothing on its own
 */
public record ScopeCandidate(String name, String protocol, String configurationId) {
}
