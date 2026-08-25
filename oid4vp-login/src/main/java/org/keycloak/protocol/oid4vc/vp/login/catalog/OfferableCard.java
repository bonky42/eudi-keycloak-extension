package org.keycloak.protocol.oid4vc.vp.login.catalog;

/**
 * A card this realm can issue, as offered to the holder.
 *
 * @param displayName     the credential scope name, shown to the holder
 * @param configurationId that scope's {@code vc.credential_configuration_id} attribute — the
 *                        identity the offer carries, never to be confused with the scope name
 */
public record OfferableCard(String displayName, String configurationId) {
}
