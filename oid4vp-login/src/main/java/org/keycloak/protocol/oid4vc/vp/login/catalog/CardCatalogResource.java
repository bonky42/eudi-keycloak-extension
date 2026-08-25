package org.keycloak.protocol.oid4vc.vp.login.catalog;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.vp.login.card.KeycloakCardGrant;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;

import java.net.URI;
import java.util.List;

/**
 * Card request page: the holder picks a card this realm can issue and walks away with the offer QR
 * code that Keycloak renders itself.
 *
 * <p><b>This component issues nothing.</b> Issuance already belongs to Keycloak: it authenticates,
 * runs the {@code verifiable_credential_offer} action and renders
 * {@code oid4vc-credential-offer.ftl} with the QR code and the offer URI. What was missing was only
 * a place to choose — hence how little code there is. The path taken is the one our own spec had
 * anticipated (§ 4, "an application requesting the issuance of a particular card"), and which
 * {@code Oid4vpIdentityProvider} already knows how to coexist with: it steps aside when
 * {@code kc_action} already holds a value.</p>
 *
 * <p><b>Why login must precede the choice.</b> The offer requires the holder to already hold the
 * entitlement ({@code UserVerifiableCredentialModel}), otherwise Keycloak refuses it with 400
 * {@code invalid_credential_offer_request}. Granting needs a user, which we only have once
 * authenticated. An anonymous visitor is therefore not shown buttons that would fail: they get a
 * link to the account console, and come back.</p>
 *
 * <p><b>Accounts are not created here.</b> Deliberate operational decision: self-registration stays
 * closed on this realm, which is exposed on the Internet. Accounts are created by an administrator.</p>
 */
public class CardCatalogResource {

    private static final Logger LOG = Logger.getLogger(CardCatalogResource.class);

    /**
     * The client the offer's pre-authorized code is bound to. {@code account-console} exists in
     * every realm and is public — it is already the {@code target_client_id} carried by the tokens
     * observed during issuance.
     */
    private static final String OFFER_CLIENT_ID = "account-console";

    private final KeycloakSession session;

    public CardCatalogResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response page() {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = authenticatedUser(realm);
        List<OfferableCard> cards = offerableCards(realm);

        StringBuilder body = new StringBuilder();
        if (user == null) {
            body.append("<p class=\"note\">Sign in first, then come back to this page.</p>")
                .append("<p><a class=\"card\" href=\"").append(escape(accountConsole(realm).toString()))
                .append("\">Sign in</a></p>");
        } else if (cards.isEmpty()) {
            body.append("<p class=\"note\">This realm defines no issuable card. ")
                .append("Create a <em>credential scope</em> carrying a ")
                .append("<code>vc.credential_configuration_id</code> and it will show up here.</p>");
        } else {
            body.append("<p class=\"note\">Hello ").append(escape(user.getUsername()))
                .append(". Pick a card: an offer QR code will be shown, to scan with your wallet.</p>");
            // Absolute, never relative — see CardOfferLink.requestUri for what a relative href did.
            String requestBase = CardOfferLink
                .requestUri(accountConsole(realm), CardCatalogResourceProviderFactory.ID).toString();
            for (OfferableCard card : cards) {
                body.append("<a class=\"card\" href=\"").append(escape(requestBase)).append("?id=")
                    .append(escape(card.configurationId())).append("\">")
                    .append(escape(card.displayName()))
                    .append("<span>").append(escape(card.configurationId())).append("</span></a>");
            }
        }
        return Response.ok(html(body.toString())).type(MediaType.TEXT_HTML_TYPE).build();
    }

    /**
     * The offerable cards, as JSON, for the account console tab.
     *
     * <p>The tab's component is a module running in the browser: it cannot read the realm's scopes.
     * It therefore queries this endpoint, which applies exactly the same rule as the HTML page
     * ({@link OfferableCards}) — one single source of truth for "which cards exist", or the two
     * views would silently drift apart.</p>
     *
     * <p>No holder data travels here: only the list of cards this realm can issue, the same for
     * everyone.</p>
     */
    @GET
    @Path("available")
    @Produces(MediaType.APPLICATION_JSON)
    public Response available() {
        return Response.ok(offerableCards(session.getContext().getRealm())).build();
    }

    /**
     * Grants the entitlement, then redirects to {@code /auth}. The grant must come first: on the way
     * back the action runs immediately, and it would then be too late.
     */
    @GET
    @Path("request")
    public Response request(@QueryParam("id") String configurationId) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = authenticatedUser(realm);
        if (user == null) {
            return Response.seeOther(accountConsole(realm)).build();
        }
        if (configurationId == null || configurationId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                .entity(html("<p class=\"note\">No card requested.</p>"))
                .type(MediaType.TEXT_HTML_TYPE).build();
        }
        if (offerableCards(realm).stream().noneMatch(c -> configurationId.equals(c.configurationId()))) {
            // We do not simply trust the parameter: without this check any value would travel to
            // /auth only to fail much further away, inside the action, with a message the holder
            // cannot relate to anything.
            LOG.warnf("Card request for unknown credential configuration '%s' in realm '%s'",
                configurationId, realm.getName());
            return Response.status(Response.Status.NOT_FOUND)
                .entity(html("<p class=\"note\">No such card in this realm.</p>"))
                .type(MediaType.TEXT_HTML_TYPE).build();
        }

        if (!new KeycloakCardGrant(session, realm, configurationId).ensureGranted(user)) {
            // KeycloakCardGrant already logs the precise reason. Without the entitlement the offer
            // would be refused with 400 by create-credential-offer: better to say so here than to
            // send the holder to a generic error screen after authentication.
            return Response.status(Response.Status.CONFLICT)
                .entity(html("<p class=\"note\">The entitlement for this card could not be granted. "
                    + "See the server logs.</p>"))
                .type(MediaType.TEXT_HTML_TYPE).build();
        }

        URI authorization = OIDCLoginProtocolService
            .authUrl(session.getContext().getUri()).build(realm.getName());
        URI target = CardOfferLink.build(authorization, OFFER_CLIENT_ID,
            CardOfferLink.accountRedirectUri(accountConsole(realm)),
            CardOfferParameter.encode(configurationId, OFFER_CLIENT_ID));
        return Response.seeOther(target).build();
    }

    private UserModel authenticatedUser(RealmModel realm) {
        // We target the static overload, which takes a third `checkActive` argument, rather than
        // instantiating an AuthenticationManager for nothing. An expired session must NOT be
        // accepted: the grant that follows writes into the holder's account.
        AuthenticationManager.AuthResult auth =
            AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        return auth == null ? null : auth.getUser();
    }

    private List<OfferableCard> offerableCards(RealmModel realm) {
        return OfferableCards.from(realm.getClientScopesStream()
            // The protocol is read from the original ClientScopeModel; it is what tells a card from
            // an ordinary OIDC scope, and the CredentialScopeModel wrapper does not change it.
            .map(scope -> new ScopeCandidate(scope.getName(), scope.getProtocol(),
                new CredentialScopeModel(scope).getCredentialConfigurationId()))
            .toList());
    }

    private URI accountConsole(RealmModel realm) {
        return Urls.accountBase(session.getContext().getUri().getBaseUri()).build(realm.getName());
    }

    private static String escape(String raw) {
        return raw == null ? "" : raw.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String html(String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            + "<title>Request a card</title><style>"
            + "body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;"
            + "background:#fff;color:#1a1a1a}"
            + "h1{font-size:1.4rem}.note{color:#555;line-height:1.5}"
            + "a.card{display:block;padding:.9rem 1rem;margin:.5rem 0;border:1px solid #d0d0d0;"
            + "border-radius:.5rem;text-decoration:none;color:inherit}"
            + "a.card:hover{border-color:#666}a.card span{display:block;font-size:.8rem;color:#666}"
            + "@media(prefers-color-scheme:dark){body{background:#161616;color:#eee}"
            + ".note{color:#aaa}a.card{border-color:#3a3a3a}a.card span{color:#999}}"
            + "</style></head><body><h1>Request a card</h1>" + body + "</body></html>";
    }
}
