package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.keycloak.common.util.Base64Url;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the {@code /auth} request that arms the offer for ONE chosen card.
 *
 * <p>This is the "the client asks for its own AIA" path that
 * {@code AuthorizationEndpoint.performActionOnParameters} copies into the authentication session's
 * client notes. Our identity provider knows about it and steps aside: when {@code kc_action} already
 * holds a value, {@code Oid4vpIdentityProvider.authenticationFinished} does not overwrite what the
 * application asked for. The two paths coexist by design, not by accident.</p>
 *
 * <p>Everything that is not {@code kc_action*} is there only so the request is accepted: an invalid
 * authorization request is rejected before those two parameters are ever read. Nobody exchanges the
 * authorization code that comes back — the holder will have their QR code by then — so the PKCE
 * verifier is not kept. It is still drawn per request: a constant challenge would be no challenge
 * at all.</p>
 */
public final class CardOfferLink {

    private static final SecureRandom RANDOM = new SecureRandom();

    private CardOfferLink() {
    }

    /**
     * Returns the return address {@code account-console} will accept.
     *
     * <p>That client registers only the pattern {@code /realms/{realm}/account/*}, and Keycloak
     * requires the slash for an address to match it — yet {@code Urls.accountBase()} returns it
     * WITHOUT a trailing slash. Passed as is, the authorization request is rejected with "Invalid
     * parameter: redirect_uri", after authentication, hence far from its cause. One character.</p>
     */
    public static String accountRedirectUri(URI accountBase) {
        String value = accountBase.toString();
        return value.endsWith("/") ? value : value + "/";
    }

    /**
     * The absolute address of the card request endpoint, derived from the account console's.
     *
     * <p>Links on the page must NOT be relative. The page is served at {@code /realms/{realm}/cards}
     * with no trailing slash, so a relative {@code demander?id=…} resolves against
     * {@code /realms/{realm}/} and lands on {@code /realms/{realm}/request} — a 404, reported by
     * the user on 2026-08-16. Prefixing with {@code cards/} only moves the problem: the same page
     * fetched with a trailing slash would then yield {@code /cards/cards/request}.</p>
     *
     * <p>The account console address is used as the anchor because it is a sibling of ours under
     * {@code /realms/{realm}/} and Keycloak already builds it for us.</p>
     */
    public static URI requestUri(URI accountBase, String providerId) {
        return accountBase.resolve(providerId + "/request");
    }

    public static URI build(URI authorizationEndpoint, String clientId, String redirectUri,
                            String actionParameter) {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", clientId);
        query.put("redirect_uri", redirectUri);
        query.put("response_type", "code");
        query.put("scope", "openid");
        query.put("state", randomUrlSafe());
        query.put("nonce", randomUrlSafe());
        // Without PKCE, a public client of the realm rejects the request with "Missing parameter:
        // code_challenge_method" — observed on 2026-08-15 — and the action is never reached.
        query.put("code_challenge", challengeFor(randomUrlSafe()));
        query.put("code_challenge_method", "S256");
        // The parameter is GLUED to the action after a colon. Keycloak's own "Issue to Wallet"
        // button does exactly this, and a separate `kc_action_parameter` — the channel our
        // 2026-08-04 spec found in the bytecode — makes this action answer
        // `missing_credential_config`. Both channels exist in the server; only this one is read here.
        query.put("kc_action", "verifiable_credential_offer:" + actionParameter);

        StringBuilder sb = new StringBuilder(authorizationEndpoint.toString()).append('?');
        boolean first = true;
        for (Map.Entry<String, String> e : query.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            first = false;
            sb.append(encode(e.getKey())).append('=').append(encode(e.getValue()));
        }
        return URI.create(sb.toString());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String randomUrlSafe() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    private static String challengeFor(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64Url.encode(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory on every JVM; its absence is not an operational condition.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
