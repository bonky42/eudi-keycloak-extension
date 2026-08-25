package org.keycloak.protocol.oid4vc.vp.login.card;

/**
 * What the re-offer rule needs to know about a presentation: its type, and the presented
 * credential's expiry ({@code null} when unknown).
 *
 * <p>Deliberately independent of {@code VerifiedPresentation}, so the rule stays a pure function
 * over minimal data, callable from a future flow authenticator that will read only session
 * notes.</p>
 */
public record PresentedCard(String vct, Long expiresAt) {
}
