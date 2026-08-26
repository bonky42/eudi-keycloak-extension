package org.keycloak.protocol.oid4vc.vp.login.broker;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.AuthenticationCallback;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.locale.LocaleUpdaterProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.vp.engine.PresentationEngine;
import org.keycloak.protocol.oid4vc.vp.login.card.CardEntitlement;
import org.keycloak.protocol.oid4vc.vp.login.card.CardGrant;
import org.keycloak.protocol.oid4vc.vp.login.card.KeycloakCardEntitlement;
import org.keycloak.protocol.oid4vc.vp.login.card.KeycloakCardGrant;
import org.keycloak.protocol.oid4vc.vp.login.card.PresentedCard;
import org.keycloak.protocol.oid4vc.vp.login.card.ReofferRule;
import org.keycloak.protocol.oid4vc.vp.login.endpoints.Oid4vpEndpoints;
import org.keycloak.protocol.oid4vc.vp.login.identity.ClaimTableIdentityResolver;
import org.keycloak.protocol.oid4vc.vp.login.identity.IdentityResolver;
import org.keycloak.protocol.oid4vc.vp.login.identity.ResolvedIdentity;
import org.keycloak.protocol.oid4vc.vp.login.protocol.ClaimsToContext;
import org.keycloak.protocol.oid4vc.vp.login.protocol.EngineFactory;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.protocol.oid4vc.vp.login.protocol.RequestedClaims;
import org.keycloak.protocol.oid4vc.vp.login.protocol.PresentationNote;
import org.keycloak.protocol.oid4vc.vp.login.protocol.QrContent;
import org.keycloak.protocol.oid4vc.vp.login.protocol.QrPng;
import org.keycloak.protocol.oid4vc.vp.login.protocol.VerifiedClaimsNotes;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.request.VerifierClientId;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Identity-brokering adapter that logs a Keycloak user in through an OID4VP
 * verifiable-presentation exchange.
 *
 * <p>The flow spans two Keycloak brokering entry points:</p>
 * <ul>
 *   <li>{@link #performLogin(AuthenticationRequest)} creates a PENDING presentation
 *       transaction via the {@link PresentationEngine} and renders {@code login-oid4vp.ftl},
 *       which shows the wallet deep-link/QR and polls the transaction status.</li>
 *   <li>{@link #callback(RealmModel, AuthenticationCallback, EventBuilder)} returns a JAX-RS
 *       resource ({@link CallbackEndpoint}) mounted under the broker endpoint path
 *       ({@code /realms/{realm}/broker/{alias}/endpoint}). It hosts the wallet/browser HTTP
 *       surface (delegating {@code request}/{@code response}/{@code status} to
 *       {@link Oid4vpEndpoints}) plus a {@code complete/{tx}} browser navigation that performs
 *       the single-use terminal read and, on success, calls
 *       {@link AuthenticationCallback#authenticated(BrokeredIdentityContext)}.</li>
 * </ul>
 *
 * <p><b>Response URI base.</b> Because {@code callback()} is what mounts the wallet/browser
 * endpoints, the engine's {@code responseUriBase} (and therefore the wallet's
 * {@code request_uri}/{@code response_uri}) points at the broker endpoint returned by
 * {@link Urls#identityProviderAuthnResponse(URI, String, String)}, not at a standalone
 * {@code /oid4vp} realm resource. The relative paths {@code request/response/status/complete}
 * are declared on {@link CallbackEndpoint} and resolve under that base.</p>
 *
 * <p><b>State round-trip.</b> The encoded {@link org.keycloak.broker.provider.util.IdentityBrokerState}
 * is carried to the browser inside {@code completeUrl} and returned as the {@code state} query
 * parameter so the callback can recover the authentication session via
 * {@link AuthenticationCallback#getAndVerifyAuthenticationSession(String)} — mirroring how the
 * OIDC broker round-trips {@code state} through the user agent. It is also stored as an auth-session
 * note ({@link #NOTE_TX}/{@link #NOTE_STATE}) so the callback can cross-check that the transaction
 * belongs to the recovered session.</p>
 *
 * <p>Not unit-tested here: exercising both entry points meaningfully requires a running Keycloak
 * (JAX-RS routing, LoginFormsProvider, broker session plumbing), covered by the Testcontainers
 * end-to-end tests.</p>
 */
public class Oid4vpIdentityProvider extends AbstractIdentityProvider<IdentityProviderModel> {

    private static final Logger LOG = Logger.getLogger(Oid4vpIdentityProvider.class);

    /** Auth-session note holding the presentation transaction id created in {@link #performLogin}. */
    public static final String NOTE_TX = "oid4vp.tx";
    /** Auth-session note holding the encoded broker state created in {@link #performLogin}. */
    public static final String NOTE_STATE = "oid4vp.state";
    /** Format tag recorded on {@link VerifiedClaimsNotes#FORMAT}: this IdP only handles SD-JWT VC presentations. */
    private static final String VC_FORMAT = "dc+sd-jwt";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The QR code's side, in pixels. 240 fits a login page without making the holder zoom, and
     *  stays readable by a phone held about thirty centimetres away. */
    private static final int QR_SIZE_PX = 240;

    public Oid4vpIdentityProvider(KeycloakSession session, IdentityProviderModel config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        KeycloakSession requestSession = request.getSession();
        RealmModel realm = request.getRealm();
        Oid4vpConfig cfg = new Oid4vpConfig(getConfig().getConfig());

        URI baseUri = request.getUriInfo().getBaseUri();
        String clientId = clientId(cfg);
        String responseUriBase = responseUriBase(baseUri, realm);

        PresentationEngine engine = EngineFactory.build(requestSession, cfg, clientId, responseUriBase);
        PresentationTransaction tx = engine.createTransaction(cfg.dcqlQuery(), cfg.ttlSeconds());

        String encodedState = request.getState().getEncoded();
        AuthenticationSessionModel authSession = request.getAuthenticationSession();
        authSession.setAuthNote(NOTE_TX, tx.getId());
        authSession.setAuthNote(NOTE_STATE, encodedState);

        String requestUri = responseUriBase + "/request/" + tx.getId();
        String walletUri = QrContent.walletUri(clientId, requestUri);
        String statusUrl = responseUriBase + "/status/" + tx.getId();
        String completeUrl = responseUriBase + "/complete/" + tx.getId()
            + "?state=" + URLEncoder.encode(encodedState, StandardCharsets.UTF_8);

        // A rendering failure must never cost the page: the deep link is enough to start the
        // journey, and it is in fact the only path in the same-device case.
        String qrDataUri = "";
        try {
            qrDataUri = QrPng.dataUri(walletUri, QR_SIZE_PX);
        } catch (RuntimeException | LinkageError e) {
            // LinkageError (e.g. NoClassDefFoundError) is caught deliberately, alongside
            // RuntimeException: if the ZXing classes are not visible from this provider's
            // classloader (a stripped distribution, a Keycloak upgrade that drops the TOTP QR
            // dependency, ...), the JVM raises NoClassDefFoundError, which is a LinkageError, not
            // a RuntimeException — it would otherwise propagate out of performLogin and kill the
            // whole login page. Throwable is deliberately NOT used here: it would also swallow
            // OutOfMemoryError and thread interruption, which must be allowed to propagate.
            LOG.warnf(e, "Failed to render the wallet QR code for tx %s; falling back to the "
                + "deep link alone", tx.getId());
        }

        LoginFormsProvider form = requestSession.getProvider(LoginFormsProvider.class);
        return form
            .setAttribute("walletUri", walletUri)
            .setAttribute("qrDataUri", qrDataUri)
            .setAttribute("statusUrl", statusUrl)
            .setAttribute("completeUrl", completeUrl)
            // What only the server knows, and what the page could not say without it. The status
            // endpoint stays as it is: it exposes the status and nothing else, deliberately, and
            // widening it would put the content of the request on an endpoint that answers anyone.
            .setAttribute("requestPurpose", cfg.requestPurpose())
            .setAttribute("requestedClaims", RequestedClaims.of(cfg.dcqlQuery()))
            .setAttribute("ttlSeconds", cfg.ttlSeconds())
            // Where the page must send a language change. Keycloak builds the switcher's own
            // links from this page's URL, which cannot be requested a second time; the template
            // repoints them here. Empty is not a case: this endpoint always exists.
            .setAttribute("localeEndpoint", responseUriBase + "/locale")
            .createForm("login-oid4vp.ftl");
    }

    /**
     * Hands the OID4VP verification metadata collected in {@code complete/{tx}} over to the user
     * session, so {@code VerifiedClaimsMapper} can read it at token issuance time.
     *
     * <p>Keycloak calls this once the brokered login is fully settled (after first-broker-login, if
     * any), with the authentication session that actually produces the user session — the notes set
     * here therefore end up on {@code UserSessionModel}. {@code BrokeredIdentityContext.setSessionNote}
     * cannot be used instead: without an authentication session attached it parks the notes in
     * {@code contextData}, which only the token-exchange path ({@code addSessionNotesToUserSession})
     * ever reads back; and with one attached, the notes written at {@code complete/{tx}} time were
     * observed (E2E) not to survive the first-broker-login flow. Carrying plain strings in the
     * context data and copying them here mirrors what {@code OIDCIdentityProvider} does for its
     * federated tokens.</p>
     *
     * <p>Every note in {@link VerifiedClaimsNotes#ALL} is written unconditionally, including when
     * this authentication carried no value for it: re-authenticating a brokered user can reuse an
     * existing {@code UserSessionModel}, and leaving an absent key untouched would let a previous
     * login's note (different presentation, different provenance) keep showing through mixed with
     * this login's other notes. Writing blank here overwrites that stale value; the reader
     * ({@code VerifiedClaimsMapper}) already treats a blank note as absent.</p>
     *
     * <p><b>Offer trigger.</b> After the notes above, this also decides (via
     * {@link ReofferRule}) whether the holder should be offered a fresh card, and if so arms the
     * {@code verifiable_credential_offer} AIA (application-initiated action) via two
     * {@link AuthenticationSessionModel} <b>client</b> notes — confirmed by disassembling Keycloak
     * 26.7.0: {@code AuthenticationManager.nextRequiredAction} reads {@link Constants#KC_ACTION} with
     * {@code getClientNote}, and the {@code AuthorizationEndpoint}'s own {@code kc_action}/
     * {@code kc_action_parameter} plumbing writes with {@code setClientNote} — never
     * {@code setAuthNote}. Three guards, all non-blocking:</p>
     * <ul>
     *   <li>a transient IdP creates no account, so there is nothing to attest and any {@code sub}
     *       we could put on a card would be invented — never offer, never touch these notes;</li>
     *   <li>{@code ownVct} unconfigured makes {@link ReofferRule#shouldOffer} inert, turning every
     *       issuance path off;</li>
     *   <li>any failure while building or writing the offer (including a half-configured
     *       {@code ownCredentialConfigId}) is logged and swallowed: the porter already proved their
     *       identity, so a broken offer must never cost them the login.</li>
     * </ul>
     * <p><b>Grant before offer.</b> Keycloak's own {@code create-credential-offer}
     * endpoint refuses (400 {@code invalid_credential_offer_request}) unless the holder already has
     * the entitlement ({@code UserVerifiableCredentialModel}) — nothing else in production grants
     * it, so right before arming the AIA (via {@link KeycloakCardGrant}, idempotent) this
     * re-grants it if missing. Assumed consequence, deliberate: because this re-grants on every
     * login that would trigger an offer, an admin revocation only lasts until the holder's next PID
     * login — "revoke in bulk, then the holder re-bootstraps by presenting their PID" is the
     * intended procedure, not a defence against a stolen PID, which already grants
     * full account access regardless of this entitlement. A failed grant is logged and skips the
     * offer, same non-blocking discipline as the three guards above.</p>
     * <p><b>What the end-to-end run settled.</b> Two fields of the offer configuration turned out
     * to be mandatory in practice, both diagnosed from a real run against Keycloak 26.7.0:
     * {@code preAuthorized} (left unset it defaults to false, and the offer becomes an
     * authorization-code offer a wallet cannot honour right after a browser login) and
     * {@code clientId} (left unset the pre-authorized code references no client and the token
     * exchange fails with « No client model for: null »). The client used is the one the porter is
     * signing into — the only one in context — which must therefore carry {@code oid4vci.enabled}.
     * The ordering question is settled too: {@code authenticationFinished} runs early enough, the
     * AIA armed here is picked up by the very next required-action evaluation.</p>
     * <p>No required action is ever persisted on the {@code UserModel}: that would stick to the user
     * and re-block every future login until a wallet is at hand.</p>
     * <p><b>{@code oid4vp.fedid} is refreshed at every login.</b> Before the offer decision above,
     * and in its own guarded block, this writes {@link ClaimsToContext#FEDID_ATTRIBUTE} onto the
     * authenticated {@code UserModel} as soon as {@link VerifiedClaimsNotes#CTX_FEDID} differs from
     * what is already there. Keycloak applies {@code ctx.setUserAttribute} — set in
     * {@code complete()} — only at the FIRST broker login: an account created before issuance
     * existed would therefore never acquire the attribute, would receive cards with no subject, and
     * would have them refused at every later presentation, with nothing in the logs explaining why.
     * The scope is deliberately narrow: {@code oid4vp.fedid} is a technical attribute, invisible to
     * the user, under no uniqueness constraint and with no part in the login decision. Neither the
     * email nor the civil status is refreshed here. Account identity no longer depends on the
     * email; the realm forbids duplicate emails, so updating to one another account already holds
     * would fail DURING the login and lock out its holder for a reason that is not theirs; and the
     * identity provider runs with {@code trustEmail: true}, so Keycloak would ask for no
     * confirmation and the login email would change silently.</p>
     */
    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
        for (String note : VerifiedClaimsNotes.ALL) {
            Object value = context.getContextData().get(note);
            String text = (value instanceof String s && !s.isBlank()) ? s : "";
            authSession.setUserSessionNote(note, text);
        }

        if (getConfig().isTransientUsers()) {
            // A transient identity provider creates no account, so there is nothing to attest and
            // a card's sub could only be invented. Leave BEFORE any action note is set
            // (kc_action / kc_action_parameter).
            return;
        }

        // Oid4vpConfig itself just wraps the raw config map — no parsing happens until an accessor
        // is called, so constructing it here is safe outside the try below.
        Oid4vpConfig cfg = new Oid4vpConfig(getConfig().getConfig());

        // oid4vp.fedid is set at EVERY login. ctx.setUserAttribute, set by complete(), is applied
        // only at the FIRST broker login: an account created before issuance existed would never
        // have it, would receive cards with no subject, and would have them refused at every
        // presentation. The scope stays deliberately limited to this technical attribute — neither
        // the email nor the civil status is refreshed: unlike oid4vp.fedid they do play a part in
        // the login (the email is under the realm's uniqueness constraint, and trustEmail true
        // would let an email change through without confirmation), and this block does not touch
        // them whatever its outcome. Its own try/catch, separate from the offer's: a failure here
        // must never prevent the re-offer evaluation further down.
        try {
            String fedid = (String) context.getContextData().get(VerifiedClaimsNotes.CTX_FEDID);
            UserModel authenticated = authSession.getAuthenticatedUser();
            if (fedid != null && authenticated != null
                    && !fedid.equals(authenticated.getFirstAttribute(ClaimsToContext.FEDID_ATTRIBUTE))) {
                authenticated.setSingleAttribute(ClaimsToContext.FEDID_ATTRIBUTE, fedid);
                LOG.debugf("Refreshed %s for user %s after login via idp %s",
                    ClaimsToContext.FEDID_ATTRIBUTE, authenticated.getId(), getConfig().getAlias());
            }
        } catch (RuntimeException e) {
            // A realm whose user profile refuses unmanaged attributes will make this write fail.
            // The holder has just proved their identity, so this is logged and the login carries
            // on — the warning further down, when the attribute is missing as the offer is armed,
            // tells the operator what it costs them.
            LOG.warnf(e, "Failed to refresh %s after login via idp %s; the cards this Keycloak "
                + "issues will carry no subject. Check the realm's unmanagedAttributePolicy",
                ClaimsToContext.FEDID_ATTRIBUTE, getConfig().getAlias());
        }

        try {
            // reissueBeforeSeconds()/expiresAt both parse admin- or wallet-influenced free text
            // (Integer.parseInt / Long.valueOf, no guard). Java evaluates all arguments before
            // invoking a call, so evaluating them as arguments to ReofferRule.shouldOffer let a
            // malformed "Re-issue Before (seconds)" admin field — it is STRING_TYPE in the console,
            // so "30d" gets through — throw a NumberFormatException that escaped
            // authenticationFinished entirely and turned an already-proven login into an error
            // page, even when ownVct was unset and issuance was meant to be inert. Every read of
            // admin-entered configuration for this decision must therefore happen inside this
            // guarded block.
            List<PresentedCard> presentedCards = List.of();
            Object rawCards = context.getContextData().get(VerifiedClaimsNotes.CTX_CARDS);
            if (rawCards instanceof String json && !json.isBlank()) {
                presentedCards = MAPPER.readValue(json, new TypeReference<List<PresentedCard>>() { });
            }
            if (!ReofferRule.shouldOffer(presentedCards, cfg.ownVct(),
                    java.time.Instant.now().getEpochSecond(), cfg.reissueBeforeSeconds())) {
                return;
            }

            if (cfg.ownCredentialConfigId() == null) {
                // Issuance is half-configured (the same idiom as KeycloakCardEntitlement): the
                // offer cannot be parameterised, so none is armed — but the login is never blocked
                // over it.
                LOG.warnf("ReofferRule wants to offer own vct %s but ownCredentialConfigId is not "
                    + "configured; issuance is only half-configured, skipping the offer", cfg.ownVct());
                return;
            }

            if (authSession.getClientNote(Constants.KC_ACTION) != null) {
                // The client may already have requested its OWN AIA via
                // ?kc_action=... on /auth (AuthorizationEndpoint.performActionOnParameters writes it
                // into this exact client note before authentication even starts). Overwriting it here
                // would silently discard whatever the application asked for and send it a
                // kc_action_status for an action it never requested. The "IdP-driven, not
                // client-driven" trigger (spec § 4) must coexist with that pre-existing path, not
                // replace it — so we simply skip our own offer this time.
                LOG.debugf("Not arming verifiable_credential_offer AIA: kc_action is already '%s' "
                    + "(client-initiated) for idp %s", authSession.getClientNote(Constants.KC_ACTION),
                    getConfig().getAlias());
                return;
            }

            // Found end to end: the offer MUST name a client. Without one, the pre-authorized code
            // it carries references no client and the token endpoint exchange fails with
            // "invalid_request / No client model for: null" — the wallet scans a QR code that leads
            // nowhere. The only client in context here is the one the holder is signing in to, so
            // that is the one issuance hangs off (Keycloak will in fact record the issued card under
            // it). An accepted consequence, worth documenting for operators: that
            // client doit porter l'attribut `oid4vci.enabled=true`, sinon
            // DefaultCredentialOfferProvider.validateTargetClient refuse l'offre — l'action native
            // se contente alors de `context.ignore()` et la connexion se termine normalement.
            //
            // This guard sits deliberately BEFORE the grant. Placed after, a session with no
            // client wrote an entitlement to the database and then armed nothing — a write on a path
            // that leads nowhere. Every condition that can make the offer be abandoned has to be
            // evaluated before the first write.
            ClientModel loginClient = authSession.getClient();
            if (loginClient == null) {
                LOG.warnf("No client on the auth session while about to arm the card offer for idp "
                    + "%s; skipping the grant and the offer", getConfig().getAlias());
                return;
            }

            // create-credential-offer requires the holder to already have the
            // entitlement (UserVerifiableCredentialModel) — without it Keycloak's own OID4VCI
            // endpoint answers 400 invalid_credential_offer_request. Nothing else in production
            // grants it, so it must happen here, before arming the offer, or the AIA we're about
            // to arm would send the holder to a page that fails every time.
            //
            // UserModel provenance (verified by disassembling keycloak-services-26.7.0.jar,
            // IdentityBrokerService): authenticationFinished is invoked from exactly one place,
            // finishBrokerAuthentication(BrokeredIdentityContext, UserModel, AuthenticationSessionModel,
            // String), itself called only by afterPostBrokerLoginFlowSuccess — reached, on the plain
            // login path, via authenticated() calling authSession.setAuthenticatedUser(user) BEFORE
            // finishOrRedirectToPostBrokerLogin(). So authSession.getAuthenticatedUser() is already
            // populated here; BrokeredIdentityContext itself exposes no getUser() at all (only
            // username strings), so it could never have served this purpose. Still guarded
            // defensively: a future Keycloak refactor changing that ordering must degrade to "skip
            // the grant and the offer", never to an NPE that would turn a proven login into an
            // error page.
            UserModel user = authSession.getAuthenticatedUser();
            if (user == null) {
                LOG.warnf("No authenticated user on the auth session while about to grant the card "
                    + "entitlement for idp %s; skipping the grant and the offer", getConfig().getAlias());
                return;
            }
            CardGrant cardGrant = createCardGrant(cfg.ownCredentialConfigId());
            if (!cardGrant.ensureGranted(user)) {
                // KeycloakCardGrant already logged the precise cause (half-configured issuance or a
                // write failure). Never arm an offer that create-credential-offer would refuse.
                return;
            }

            // The card this offer will have issued draws its `sub` from the oid4vp.fedid user
            // attribute, through oid4vc-subject-id-mapper. The block higher up in this same method
            // now writes it straight onto the UserModel at EVERY login — but that block is itself
            // non-blocking (its own try/catch), so the attribute can still be missing here: either a
            // realm that never set `unmanagedAttributePolicy` (Keycloak 26 refuses unmanaged
            // attributes by default) made that write fail, or
            // context.getContextData().get(CTX_FEDID) was null. Without it the mapper sets NO
            // subject: the holder is offered a card at every PID login, receives it with no `sub`,
            // and has it refused at every presentation
            // (fail-closed, and correct) — with no signal anywhere saying why. The offer is NOT
            // cancelled over it (issuance does not decide the login, and a card with no sub stays
            // harmless because it is refused), but the operator is told.
            if (user.getFirstAttribute(ClaimsToContext.FEDID_ATTRIBUTE) == null) {
                LOG.warnf("Arming a card offer for user %s while attribute %s is unset: the issued "
                    + "card will carry no subject and will be refused at every login. Check that "
                    + "the realm's user profile allows unmanaged attributes "
                    + "(unmanagedAttributePolicy) and that this account went through a phase-3b "
                    + "first broker login via idp %s",
                    user.getId(), ClaimsToContext.FEDID_ATTRIBUTE, getConfig().getAlias());
            }

            // The format was established by reading the bytecode of
            // VerifiableCredentialOfferActionConfig (org.keycloak.keycloak-core-26.7.0.jar):
            // kc_action_parameter is that bean's JSON, Base64Url encoded — never the bare
            // configuration id. asEncodedParameter() does exactly what
            // VerifiableCredentialOfferAction.getActionConfig expects back from decodeConfig, so the
            // Keycloak class is reused rather than the encoding reproduced by hand.
            //
            // Found end to end and confirmed against the bytecode of
            // VerifiableCredentialOfferAction: leaving `preAuthorized` null means FALSE, and the
            // offer built is then an
            // AuthorizationCodeGrant (`issuer_state`) — le wallet devrait rejouer un authorization
            // code flow complet dans un navigateur pour obtenir la carte. Or ici le porteur VIENT de
            // proved their identity in that very browser: the pre-authorized grant is the only one
            // that makes sense, and the only one a wallet — which holds nothing but cards — can
            // honour. It requires the `oid4vc-vci-preauth-code` feature; without it
            // DefaultCredentialOfferProvider raises a CredentialOfferException that the action
            // handles with `context.ignore()`, so the login still finishes, discipline unchanged.
            VerifiableCredentialOfferActionConfig actionConfig = new VerifiableCredentialOfferActionConfig();
            actionConfig.setCredentialConfigurationId(cfg.ownCredentialConfigId());
            actionConfig.setClientId(loginClient.getClientId());
            actionConfig.setPreAuthorized(true);
            String encodedParameter = actionConfig.asEncodedParameter();

            // Notes de session d'authentification CLIENT uniquement (jamais une required action sur
            // the UserModel, which would stick to the user and re-block every login until they had
            // a wallet at hand). If the offer does not fire on the first end-to-end run, this log
            // confirms the notes were indeed set here — what then remains to check is whether
            // authenticationFinished runs before required actions are evaluated.
            authSession.setClientNote(Constants.KC_ACTION, "verifiable_credential_offer");
            authSession.setClientNote(Constants.KC_ACTION_PARAMETER, encodedParameter);
            LOG.debugf("Armed verifiable_credential_offer AIA (credentialConfigurationId=%s) after "
                + "login via idp %s", cfg.ownCredentialConfigId(), getConfig().getAlias());
        } catch (IOException | RuntimeException e) {
            // Issuance must NEVER block the login: the holder has just proved their identity. This
            // logs precisely and lets the login finish. It covers an encoding failure as well as
            // unparseable free text from an administrator (reissueBeforeSeconds) or an unexpected
            // expiresAt value.
            LOG.warnf(e, "Failed to arm verifiable_credential_offer AIA for own vct %s via idp %s",
                cfg.ownVct(), getConfig().getAlias());
        }
    }

    /**
     * Builds the {@link CardGrant} used by {@link #authenticationFinished}. A seam rather than a
     * direct {@code new KeycloakCardGrant(...)} call so {@code Oid4vpIdentityProviderTest} — which
     * exercises {@code authenticationFinished} with {@code session == null} to stay Keycloak-free —
     * can override it; {@link KeycloakCardGrant} itself needs a real {@link KeycloakSession} and is
     * exercised only by the Testcontainers suite, the same boundary as the rest of this
     * class's Keycloak-touching code (see class javadoc).
     */
    protected CardGrant createCardGrant(String credentialConfigId) {
        return new KeycloakCardGrant(session, session.getContext().getRealm(), credentialConfigId);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        URI baseUri = session.getContext().getUri().getBaseUri();
        Oid4vpConfig cfg = new Oid4vpConfig(getConfig().getConfig());
        PresentationEngine engine = EngineFactory.build(session, cfg, clientId(cfg), responseUriBase(baseUri, realm));
        Oid4vpEndpoints endpoints = new Oid4vpEndpoints(session, engine);
        return new CallbackEndpoint(this, callback, getConfig(), cfg, engine, endpoints);
    }

    /**
     * OID4VP presentations are single-use and no broker token is persisted, so there is nothing
     * to hand back to a token-retrieval request. Returns {@code null} (no stored token).
     */
    @Override
    public Response retrieveToken(KeycloakSession session, org.keycloak.models.FederatedIdentityModel identity) {
        return null;
    }

    @Override
    public Response retrieveToken(KeycloakSession session, org.keycloak.models.FederatedIdentityModel identity,
                                  org.keycloak.models.UserSessionModel userSession,
                                  org.keycloak.models.UserModel user) {
        return null;
    }

    /**
     * The {@code client_id} announced to the wallet is the fingerprint of the certificate that
     * signs the Request Object — {@code x509_hash}, the scheme the EUDI reference verifier uses.
     *
     * <p>It used to be derived from the hostname ({@code x509_san_dns:}). That link does not hold:
     * the access certificate the EUDI registry issues carries no {@code dNSName}, its SAN is a URI,
     * and the registry takes no CSR — so we do not choose what the certificate contains. Drawing it
     * from the certificate itself also makes the identifier and its proof ({@code x5c}) come from
     * one source, where two separate sources could drift apart.
     */
    static String clientId(Oid4vpConfig cfg) {
        return VerifierClientId.x509Hash(cfg.signingCert());
    }

    private String responseUriBase(URI baseUri, RealmModel realm) {
        // Signature Keycloak : identityProviderAuthnResponse(baseUri, providerAlias, realmName)
        // -> /realms/{realm}/broker/{alias}/endpoint. The alias/realm order must not be swapped.
        return Urls.identityProviderAuthnResponse(baseUri, getConfig().getAlias(), realm.getName()).toString();
    }

    /**
     * JAX-RS resource returned by {@link #callback}. It is mounted under the broker endpoint
     * base path, so its relative {@code @Path} declarations expose the full wallet/browser
     * surface at {@code .../endpoint/request|response|status|complete/{tx}}.
     *
     * <p>The wallet-facing {@code request}/{@code response} and the browser-polled {@code status}
     * are pure pass-throughs to {@link Oid4vpEndpoints}; {@code complete} is the identity-provider
     * step that consumes the terminal transaction exactly once and hands the verified identity to
     * Keycloak's broker via {@link AuthenticationCallback#authenticated(BrokeredIdentityContext)}.</p>
     */
    public static class CallbackEndpoint {

        private final Oid4vpIdentityProvider provider;
        private final AuthenticationCallback callback;
        private final IdentityProviderModel config;
        private final Oid4vpConfig cfg;
        private final PresentationEngine engine;
        private final Oid4vpEndpoints endpoints;

        CallbackEndpoint(Oid4vpIdentityProvider provider, AuthenticationCallback callback,
                         IdentityProviderModel config, Oid4vpConfig cfg,
                         PresentationEngine engine, Oid4vpEndpoints endpoints) {
            this.provider = provider;
            this.callback = callback;
            this.config = config;
            this.cfg = cfg;
            this.engine = engine;
            this.endpoints = endpoints;
        }

        @GET
        @Path("request/{tx}")
        @Produces("application/oauth-authz-req+jwt")
        public Response request(@PathParam("tx") String tx) {
            return endpoints.request(tx);
        }

        @POST
        @Path("response/{tx}")
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        public Response response(@PathParam("tx") String tx,
                                 @FormParam("response") String encryptedResponse,
                                 @FormParam("error") String walletError) {
            return endpoints.response(tx, encryptedResponse, walletError);
        }

        @GET
        @Path("status/{tx}")
        @Produces(MediaType.APPLICATION_JSON)
        public String status(@PathParam("tx") String tx) {
            return endpoints.status(tx);
        }

        /**
         * Language switch for the login page this provider renders.
         *
         * <p><b>Why this exists at all.</b> Keycloak's own switcher navigates to the current page's
         * URL with {@code kc_locale} appended, and {@code LocaleUtil.processLocaleParam} turns that
         * parameter into the {@code KEYCLOAK_LOCALE} cookie. That works for pages served by
         * {@code /login-actions/authenticate}, which can be re-requested. Ours is rendered by
         * {@code performLogin} at {@code /broker/{alias}/login}, which requires a single-use
         * {@code session_code} the switcher does not carry — so the switcher's link answers 400.
         * This endpoint is the missing destination: the template rewrites each option to point
         * here, keeping the query string Keycloak already built.</p>
         *
         * <p><b>Why the cookie is written here and not in the browser.</b> {@code KEYCLOAK_LOCALE}
         * is declared {@code HttpOnly} ({@code CookieType.LOCALE}), so a {@code document.cookie}
         * write that would overwrite an existing one is rejected by the browser without an error.
         * Delegating to {@link LocaleUpdaterProvider} is also what makes the cookie's path, scope
         * and {@code SameSite}/{@code Secure} attributes correct by construction rather than
         * replicated — a replica would drift the day Keycloak changes them.</p>
         *
         * <p><b>Unknown locales are ignored, never rejected.</b> A value outside the realm's
         * supported set leaves the cookie untouched and still restarts the flow, so the holder
         * lands on a working page in the language they already had. Answering an error instead
         * would turn a cosmetic request into a dead end, and the value arrives from a query
         * parameter anyone can edit.</p>
         */
        @GET
        @Path("locale")
        public Response locale(@QueryParam("kc_locale") String requestedLocale,
                               @QueryParam("client_id") String clientId,
                               @QueryParam("tab_id") String tabId,
                               @QueryParam("client_data") String clientData) {
            KeycloakSession session = provider.session;
            RealmModel realm = session.getContext().getRealm();

            if (realm.isInternationalizationEnabled() && requestedLocale != null
                && realm.getSupportedLocalesStream().anyMatch(requestedLocale::equals)) {
                session.getProvider(LocaleUpdaterProvider.class).updateLocaleCookie(requestedLocale);
            }

            // skip_logout=true is NOT a detail. Left false (the endpoint's default), restarting the
            // flow calls AuthenticationManager.backchannelLogout on the SSO session that shares the
            // root authentication session's id — so changing the page language would sign the
            // holder out of every other application in the realm. Verified against 26.7.0 bytecode
            // (LoginActionsService.restartSession).
            URI restart = Urls.realmLoginRestartPage(
                session.getContext().getUri().getBaseUri(), realm.getName(),
                clientId, tabId, clientData, true);
            return Response.status(Response.Status.FOUND).location(restart).build();
        }

        /**
         * Browser navigation target reached once polling observes {@code completed}. Performs the
         * single-use terminal read; on a COMPLETED transaction it rebuilds a
         * {@link VerifiedPresentation} from the persisted claims, maps it onto a
         * {@link BrokeredIdentityContext} and resumes the Keycloak login. Any other outcome
         * (failed, expired, absent, already consumed) yields a generic broker error.
         */
        @GET
        @Path("complete/{tx}")
        public Response complete(@PathParam("tx") String txId, @QueryParam("state") String encodedState) {
            // Recover (and verify) the authentication session FIRST, from the round-tripped state:
            // a forged/invalid state must be rejected before it can consume a valid transaction, and
            // both the success and error branches below need the session established (mirrors
            // AbstractOAuth2IdentityProvider.Endpoint, which resolves the session up front then branches).
            AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(encodedState);

            // Cross-check that this transaction id actually belongs to the recovered session,
            // BEFORE the transaction is consumed: without this, a valid state for session A could
            // be replayed against a completed transaction id belonging to session B (the state
            // round-trip authenticates the session, not the tx path parameter).
            if (!txId.equals(authSession.getAuthNote(NOTE_TX))) {
                return callback.error(config, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            PresentationTransaction tx = engine.pollAndConsumeIfTerminal(txId);
            if (tx == null || tx.getStatus() != TransactionStatus.COMPLETED) {
                return callback.error(config, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            List<VerifiedPresentation> presentations = tx.getPresentations() == null
                ? List.of() : new ArrayList<>(tx.getPresentations());

            // Resolution goes behind a narrow interface — "given these verified presentations,
            // what is the federated identifier?". Today's implementation reads the
            // vct -> subject claim table; the device-management one will query the credential's
            // registration instead, without this call site changing.
            IdentityResolver resolver = new ClaimTableIdentityResolver(
                cfg.subjectClaimByVct(), cfg.subjectClaim(), cfg.ownVct());
            CardEntitlement entitlement = new KeycloakCardEntitlement(
                provider.session, provider.session.getContext().getRealm(),
                config.getAlias(), cfg.ownCredentialConfigId());

            ResolvedIdentity identity = resolveEntitled(presentations, resolver, entitlement, cfg.ownVct(), txId);

            // Checked BEFORE the "no stable subject" guard below. When the
            // only presentation was discarded for a revoked entitlement, presentations ends up empty
            // AND identity is null — the OTHER guard's message ("no presentation carries a usable
            // stable subject") would be factually wrong there: there WAS one, its right was refused.
            // This guard's message is accurate for that case and subsumes it.
            if (presentations.isEmpty()) {
                LOG.warnf("Nothing left to authenticate tx %s with; rejecting login", txId);
                return callback.error(config, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
            if (identity == null && !config.isTransientUsers()) {
                LOG.warnf("No presentation of tx %s carries a usable stable subject; rejecting login",
                    txId);
                return callback.error(config, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            // The transient path: no durable account, so a random per-login identifier is
            // acceptable, and nothing is persisted under it. stableSubjectId stays null, which
            // forbids setting oid4vp.fedid or attesting anything — see applyFederatedId.
            VerifiedPresentation source =
                identity != null ? identity.source() : presentations.get(0);
            String stableSubjectId = identity != null ? identity.federatedId() : null;
            String subjectId = stableSubjectId;
            if (subjectId == null) {
                byte[] random = new byte[32];
                new java.security.SecureRandom().nextBytes(random);
                subjectId = source.getIssuer() + ":"
                    + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            }

            BrokeredIdentityContext ctx = new BrokeredIdentityContext(subjectId, config);
            ctx.setIdp(provider);
            ClaimsToContext.apply(source,
                ClaimsToContext.mergedClaims(presentations, cfg.ownVct()),
                ctx, cfg.matchingClaim(), cfg.subjectClaim());
            ClaimsToContext.applyFederatedId(ctx, stableSubjectId);

            // The flat notes describe the presentation that FOUNDED THE IDENTITY: that is what
            // their readers expect of them, including the future conditional authenticator, which
            // reads
            // oid4vp.vc.vct pour brancher un sous-flux par type de carte).
            String verifiedAt = java.time.Instant.now().toString();
            noteIfPresent(ctx, VerifiedClaimsNotes.ISSUER, source.getIssuer());
            noteIfPresent(ctx, VerifiedClaimsNotes.VCT, source.getVct());
            ctx.getContextData().put(VerifiedClaimsNotes.FORMAT, VC_FORMAT);
            noteIfPresent(ctx, VerifiedClaimsNotes.TRUST_ANCHOR, source.getTrustAnchorSubject());
            ctx.getContextData().put(VerifiedClaimsNotes.VERIFIED_AT, verifiedAt);

            // ... while the array note carries EVERY presentation, each with its own framework.
            List<PresentationNote> notes = new ArrayList<>();
            List<PresentedCard> cards = new ArrayList<>();
            for (VerifiedPresentation presentation : presentations) {
                notes.add(new PresentationNote(presentation.getIssuer(), presentation.getVct(),
                    VC_FORMAT, presentation.getTrustAnchorSubject(), verifiedAt,
                    presentation.getClaims()));
                cards.add(new PresentedCard(presentation.getVct(), presentation.getExpiresAt()));
            }
            try {
                ctx.getContextData().put(VerifiedClaimsNotes.PRESENTATIONS,
                    PresentationNote.toJson(notes));
                ctx.getContextData().put(VerifiedClaimsNotes.CTX_CARDS, MAPPER.writeValueAsString(cards));
            } catch (RuntimeException | JsonProcessingException e) {
                // Fail closed but not fatal: never interrupt an already proven login over a
                // serialisation mishap. The mapper simply emits no verified_claims, and the
                // re-offer rule sees an empty list — so it offers, never the reverse.
                LOG.warnf(e, "Failed to serialize the verified presentations of tx %s", txId);
            }
            if (stableSubjectId != null) {
                ctx.getContextData().put(VerifiedClaimsNotes.CTX_FEDID, stableSubjectId);
            }

            ctx.setAuthenticationSession(authSession);
            return callback.authenticated(ctx);
        }

        /** Records a context-data entry only when {@code value} is non-null. */
        private static void noteIfPresent(BrokeredIdentityContext ctx, String name, String value) {
            if (value != null) {
                ctx.getContextData().put(name, value);
            }
        }

        /**
         * A pure extraction of the "entitlement revoked on our card: discard that presentation and
         * re-resolve the identity on what remains" loop. Behaviour is identical to before the
         * extraction, WARN and termination guard included; it is an extraction, not a rewrite, made
         * so that this security relaxation — the login used to be refused outright, and is now
         * discarded and re-resolved — is finally testable without Keycloak.
         *
         * <p><b>Deliberate mutation:</b> {@code presentations} is reduced in place, one entry at a
         * time, for every presentation discarded over a revoked entitlement. {@link #complete}
         * depends on that for its own "nothing usable left" guard once this method returns.</p>
         *
         * @return the identity retained, or {@code null} if no remaining presentation carries one —
         *         entitlement revoked on the last usable card, or the termination guard fired
         */
        static ResolvedIdentity resolveEntitled(List<VerifiedPresentation> presentations,
                                                 IdentityResolver resolver, CardEntitlement entitlement,
                                                 String ownVct, String txId) {
            ResolvedIdentity identity = null;
            while (!presentations.isEmpty()) {
                identity = resolver.resolve(presentations);
                if (identity == null) {
                    break;
                }
                if (CardEntitlement.cardAccepted(identity.source().getVct(), ownVct,
                        identity.federatedId(), entitlement)) {
                    break;
                }
                // A revoked entitlement DISCARDS this card and the identity is re-resolved on what
                // remains. Like an expiry, that is a lifecycle event, not a sign of attack. Without
                // it, the unified journey would make the documented operating procedure impossible
                // — "revoke in bulk, and the holder re-bootstraps by presenting their PID" — since
                // the wallet now presents both cards. Nothing is weakened: a thief holding the PID
                // has full access anyway, which the earlier design already accepted.
                LOG.warnf("Card of type %s presented for tx %s: entitlement check refused holder %s "
                    + "(see prior WARN for the exact reason); discarding that presentation and "
                    + "resolving the identity on what remains",
                    identity.source().getVct(), txId, identity.federatedId());
                // Termination guard: IdentityResolver only promises "the identity retained, or null"
                // (see its javadoc) — nothing requires ResolvedIdentity.source() to be reference-equal
                // to an element of `presentations`, and VerifiedPresentation has no equals(), so
                // remove() is a reference match. The interface javadoc explicitly anticipates a future
                // implementation that resolves via a credential registry lookup, which could plausibly
                // rebuild a VerifiedPresentation instead of returning the input instance. Were that to
                // happen without this guard, the list would never shrink and this while loop would spin
                // forever on an HTTP callback thread instead of producing an error page. Keep this guard
                // even though today's resolver always returns an input element.
                if (!presentations.remove(identity.source())) {
                    LOG.warnf("Resolved presentation for tx %s could not be removed from the candidate "
                        + "list (resolver returned an instance not in the input list); rejecting login "
                        + "rather than risk spinning", txId);
                    identity = null;
                    break;
                }
                identity = null;
            }
            return identity;
        }
    }
}
