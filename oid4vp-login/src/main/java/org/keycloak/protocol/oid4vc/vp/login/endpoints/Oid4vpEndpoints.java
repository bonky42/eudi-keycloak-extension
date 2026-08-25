package org.keycloak.protocol.oid4vc.vp.login.endpoints;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.vp.engine.PresentationEngine;
import org.keycloak.protocol.oid4vc.vp.login.protocol.StatusDto;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;

/**
 * JAX-RS resource exposing the wallet/browser-facing HTTP surface of an OID4VP
 * presentation transaction: the signed Request Object the wallet fetches
 * ({@code request/{tx}}), the {@code direct_post} response the wallet submits
 * back ({@code response/{tx}}), and the non-consuming status the browser polls
 * while waiting for the wallet ({@code status/{tx}}).
 *
 * <p>A thin adapter over {@link PresentationEngine}: all
 * transaction lifecycle logic lives there. This class only translates between
 * HTTP and the engine's API, and maps {@link VpVerificationException} to HTTP
 * status codes.</p>
 *
 * <p>The {@code status} endpoint deliberately uses {@link PresentationEngine#peek(String)}
 * rather than {@link PresentationEngine#pollAndConsumeIfTerminal(String)}: a browser may
 * poll status repeatedly while the wallet is still interacting, and polling must never
 * itself consume the single-use terminal transaction. The actual one-time consumption of
 * a terminal transaction happens in the identity provider callback, which calls
 * {@code pollAndConsumeIfTerminal} to retrieve the verified claims exactly once.</p>
 *
 * <p>Not unit-tested directly: exercising these endpoints meaningfully requires a real
 * JAX-RS/servlet runtime plus a real {@link PresentationEngine}, which is covered by the
 * Testcontainers end-to-end tests. The one piece of pure logic here — the
 * {@link VpErrorCode} to HTTP status mapping — is extracted as {@link #statusFor(VpErrorCode)}
 * and covered by a plain unit test.</p>
 */
public class Oid4vpEndpoints {

    private final KeycloakSession session;
    private final PresentationEngine engine;

    public Oid4vpEndpoints(KeycloakSession session, PresentationEngine engine) {
        this.session = session;
        this.engine = engine;
    }

    /**
     * Returns the signed Request Object JWT for the transaction, as fetched by the wallet
     * via the {@code request_uri} embedded in the QR/deep-link. 404 if the transaction is
     * unknown (never created, or expired from the store).
     */
    @GET
    @Path("request/{tx}")
    @Produces("application/oauth-authz-req+jwt")
    public Response request(@PathParam("tx") String tx) {
        try {
            String jwt = engine.getRequestObject(tx);
            return Response.ok(jwt).build();
        } catch (VpVerificationException e) {
            return Response.status(statusFor(e.getCode())).build();
        }
    }

    /**
     * Receives the wallet's {@code direct_post.jwt} response: a single {@code response} form
     * parameter holding a compact JWE.
     *
     * <p>{@code error} is still accepted in the clear, beside it. A wallet that refuses often has
     * no negotiated key at that point, and demanding encryption there would turn a legible refusal
     * into a decryption failure — losing {@link VpErrorCode#WALLET_ERROR}, which works today.
     *
     * <p>Always answers 200: under direct_post the outcome is not conveyed here but discovered by
     * the browser polling {@code status/{tx}}.
     */
    @POST
    @Path("response/{tx}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response response(@PathParam("tx") String tx,
                              @FormParam("response") String encryptedResponse,
                              @FormParam("error") String walletError) {
        if (walletError != null && !walletError.isBlank()) {
            engine.failFromWallet(tx, walletError);
        } else {
            engine.processEncryptedWalletResponse(tx, encryptedResponse, "dc+sd-jwt");
        }
        // An explicit JSON body, and a Content-Type through @Produces: Keycloak answers 500 to any
        // response without a MediaType. The direct_post wallet expects no useful content here; the
        // browser discovers the outcome by polling status/{tx}.
        return Response.ok("{}").type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * Non-consuming status read, polled by the browser while waiting for the wallet.
     * Exposes only {@link StatusDto#status} — never claims or a precise error code.
     */
    @GET
    @Path("status/{tx}")
    @Produces(MediaType.APPLICATION_JSON)
    public String status(@PathParam("tx") String tx) {
        return StatusDto.of(engine.peek(tx)).toJson();
    }

    /**
     * Maps a {@link VpErrorCode} to the HTTP status returned by {@link #request(String)}.
     * {@link VpErrorCode#TRANSACTION_NOT_FOUND} maps to 404 (the transaction is absent or
     * expired — nothing the client did wrong, they can just start over). Every other code
     * {@link PresentationEngine#getRequestObject} can throw — including
     * {@link VpErrorCode#TRANSACTION_MISSING_ENCRYPTION_KEY}, a known-but-unservable transaction —
     * maps to 500: these are server-side invariant violations, not a client-facing "not found".
     * Extracted as a pure method so the mapping can be unit-tested without a JAX-RS runtime.
     */
    static Response.Status statusFor(VpErrorCode code) {
        return code == VpErrorCode.TRANSACTION_NOT_FOUND
            ? Response.Status.NOT_FOUND
            : Response.Status.INTERNAL_SERVER_ERROR;
    }
}
