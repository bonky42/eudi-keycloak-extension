package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pins the shape of the {@code /auth} request the page issues to arm the offer.
 *
 * <p>The mechanism targeted is {@code AuthorizationEndpoint.performActionOnParameters}, which copies
 * {@code kc_action} / {@code kc_action_parameter} from the request into the authentication session's
 * CLIENT notes — the very channel {@code AuthenticationManager.nextRequiredAction} reads back. Every
 * other parameter is there only so the request is accepted: an invalid {@code /auth} request is
 * rejected before those two are ever read.</p>
 *
 * <p><b>PKCE is not decorative.</b> A {@code curl} attempt without it, on 2026-08-15, was rejected
 * with "Missing parameter: code_challenge_method": public clients of the realm require it. Nobody
 * exchanges the authorization code that comes back — so no verifier is kept — but its absence would
 * fail the request before the offer.</p>
 */
class CardOfferLinkTest {

    private static final URI AUTH = URI.create(
        "https://accounts.oid4vp.eu/realms/oid4vp-demo/protocol/openid-connect/auth");
    private static final String REDIRECT = "https://accounts.oid4vp.eu/realms/oid4vp-demo/account/";

    @Test
    void parameterTravelsGluedToTheActionAfterAColon() {
        // Copied from Keycloak's own "Issue to Wallet" button, observed on 2026-08-17:
        //   kc_action=verifiable_credential_offer:<base64>
        // Sending it as a separate kc_action_parameter — the channel our 2026-08-04 spec had found
        // in the bytecode — makes the action answer `missing_credential_config`. Both channels
        // exist; only this one is read by this action.
        String parameter = CardOfferParameter.encode("eudi-pid", "account-console");

        Map<String, String> query = queryOf(CardOfferLink.build(AUTH, "account-console", REDIRECT, parameter));

        assertEquals("verifiable_credential_offer:" + parameter, query.get("kc_action"));
        assertNull(query.get("kc_action_parameter"),
            "a separate parameter is not read by this action and only muddies the request");
    }

    @Test
    void isAValidAuthorizationRequestSoTheActionIsEverReached() {
        String parameter = CardOfferParameter.encode("eudi-pid", "account-console");

        Map<String, String> query = queryOf(CardOfferLink.build(AUTH, "account-console", REDIRECT, parameter));

        assertEquals("code", query.get("response_type"));
        assertEquals("openid", query.get("scope"));
        assertEquals("account-console", query.get("client_id"));
        assertEquals(REDIRECT, query.get("redirect_uri"));
        assertEquals("S256", query.get("code_challenge_method"),
            "without PKCE a public client of the realm rejects the request with 'Missing parameter: "
                + "code_challenge_method' and the offer is never reached");
        assertTrue(query.get("code_challenge") != null && !query.get("code_challenge").isBlank());
    }

    @Test
    void twoRequestsNeverShareTheirStateOrChallenge() {
        String parameter = CardOfferParameter.encode("eudi-pid", "account-console");

        Map<String, String> first = queryOf(CardOfferLink.build(AUTH, "account-console", REDIRECT, parameter));
        Map<String, String> second = queryOf(CardOfferLink.build(AUTH, "account-console", REDIRECT, parameter));

        assertNotEquals(first.get("state"), second.get("state"),
            "a replayed state would make two requests indistinguishable");
        assertNotEquals(first.get("code_challenge"), second.get("code_challenge"),
            "the PKCE challenge is drawn per request: sharing it would amount to having none");
    }

    @Test
    void accountRedirectAlwaysEndsWithASlash() {
        // The `account-console` client registers only the pattern /realms/{realm}/account/*, and
        // Keycloak requires the slash for an address to match it. Yet Urls.accountBase() returns it
        // WITHOUT a trailing slash: passing it as is yields "Invalid parameter: redirect_uri" —
        // and only AFTER authentication, far from the cause.
        assertEquals("https://accounts.oid4vp.eu/realms/oid4vp-demo/account/",
            CardOfferLink.accountRedirectUri(
                URI.create("https://accounts.oid4vp.eu/realms/oid4vp-demo/account")));
    }

    @Test
    void anAlreadySlashedAccountRedirectIsLeftAlone() {
        assertEquals("https://accounts.oid4vp.eu/realms/oid4vp-demo/account/",
            CardOfferLink.accountRedirectUri(
                URI.create("https://accounts.oid4vp.eu/realms/oid4vp-demo/account/")),
            "doubling the slash would break the match as surely as omitting it");
    }

    @Test
    void requestUriIsAbsoluteAndSiblingOfTheAccountConsole() {
        // A relative "request?id=…" href resolves against /realms/{realm}/ — the page is served at
        // /realms/{realm}/cards with no trailing slash — and lands on /realms/{realm}/request,
        // a 404 reported by the user on 2026-08-16. This pins the shape rather than reasoning about
        // URI.resolve() from memory, which is exactly how the first fix went wrong.
        assertEquals("https://accounts.oid4vp.eu/realms/oid4vp-demo/cards/request",
            CardOfferLink.requestUri(
                URI.create("https://accounts.oid4vp.eu/realms/oid4vp-demo/account"),
                "cards").toString());
    }

    private static Map<String, String> queryOf(URI uri) {
        Map<String, String> out = new HashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            out.put(java.net.URLDecoder.decode(pair.substring(0, eq), UTF_8),
                java.net.URLDecoder.decode(pair.substring(eq + 1), UTF_8));
        }
        return out;
    }
}
