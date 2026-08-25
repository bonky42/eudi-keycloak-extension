package org.keycloak.protocol.oid4vc.vp.engine;

import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.model.PresentationTransaction;
import org.keycloak.protocol.oid4vc.vp.model.TransactionStatus;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.request.RequestObjectBuilder;
import org.keycloak.protocol.oid4vc.vp.request.ResponseEncryptionKey;
import org.keycloak.protocol.oid4vc.vp.store.TransactionStore;
import org.keycloak.protocol.oid4vc.vp.trust.TrustPolicy;
import org.keycloak.protocol.oid4vc.vp.verifier.EncryptedResponse;
import org.keycloak.protocol.oid4vc.vp.verifier.PresentationRequestContext;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpTokenResponse;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;

import org.jboss.logging.Logger;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Orchestrates the lifecycle of an OID4VP presentation transaction, tying together the
 * {@link TransactionStore}, the {@link RequestObjectBuilder} and the per-format
 * {@link VpVerifier}s: creating a PENDING transaction, issuing its signed Request Object, routing
 * the wallet's {@code direct_post} response to the matching verifier, recording a wallet-side
 * error, and single-use terminal polling.
 *
 * <p>This is the core-facing API; the login and API facades are thin adapters over it.</p>
 */
public class PresentationEngine {

    private static final Logger LOG = Logger.getLogger(PresentationEngine.class);

    /**
     * Fixed TTL, in seconds, for every Request Object this engine issues. The
     * {@link TransactionStore} does not expose on read the TTL passed to {@code put}, and widening
     * that contract only to thread the value back was not worth it: one request-object lifetime is
     * how a verifier deployment is normally configured anyway.
     */
    static final int REQUEST_OBJECT_TTL_SECONDS = 120;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();
    private static final int TOKEN_BYTES = 32;

    private final TransactionStore store;
    private final RequestObjectBuilder requestBuilder;
    private final Map<String, VpVerifier> verifiers;
    private final TrustPolicy trustPolicy;
    private final String clientId;
    private final String responseUri;
    private final Clock clock;

    public PresentationEngine(TransactionStore store, RequestObjectBuilder requestBuilder,
                               Map<String, VpVerifier> verifiers, TrustPolicy trustPolicy,
                               String clientId, String responseUri, Clock clock) {
        this.store = store;
        this.requestBuilder = requestBuilder;
        this.verifiers = verifiers;
        this.trustPolicy = trustPolicy;
        this.clientId = clientId;
        this.responseUri = responseUri;
        this.clock = clock;
    }

    /**
     * Creates and stores a new PENDING transaction: random (SecureRandom, 32 bytes,
     * base64url-nopad) id/nonce/state, {@code createdAt} from the engine clock, the
     * DCQL query serialized onto the transaction, and a fresh {@link ResponseEncryptionKey}
     * generated for this transaction alone (HAIP requires a response-encryption key pair
     * specific to each Authorization Request; it must never be shared across transactions).
     */
    public PresentationTransaction createTransaction(DcqlQuery query, int ttlSeconds) {
        PresentationTransaction tx = new PresentationTransaction();
        tx.setId(randomToken());
        tx.setNonce(randomToken());
        tx.setState(randomToken());
        tx.setStatus(TransactionStatus.PENDING);
        tx.setCreatedAt(clock.instant().getEpochSecond());
        tx.setDcqlQueryJson(query.toJson());
        ResponseEncryptionKey encryptionKey = ResponseEncryptionKey.generate();
        tx.setResponseEncKid(encryptionKey.kid());
        tx.setResponseEncPrivateKey(encryptionKey.privateKeyB64());
        tx.setResponseEncPublicKey(encryptionKey.publicKeyB64());
        store.put(tx, ttlSeconds);
        return tx;
    }

    /**
     * Builds the signed Request Object JWT for the given transaction.
     *
     * @throws VpVerificationException with {@link VpErrorCode#TRANSACTION_NOT_FOUND} if the
     *                                  transaction is unknown (absent or expired from the store),
     *                                  or with {@link VpErrorCode#TRANSACTION_MISSING_ENCRYPTION_KEY}
     *                                  if it has no response-encryption key material
     */
    public String getRequestObject(String txId) throws VpVerificationException {
        PresentationTransaction tx = store.get(txId);
        if (tx == null) {
            throw new VpVerificationException(VpErrorCode.TRANSACTION_NOT_FOUND,
                "no pending transaction for id " + txId);
        }
        // Fail closed: build() unconditionally embeds the transaction's own key in
        // client_metadata, so a transaction without one (e.g. minted by a node predating this
        // feature, then read back here from the shared store) must never reach it — we must never
        // serve a direct_post.jwt request object without a real key to encrypt the response to.
        if (tx.getResponseEncKid() == null || tx.getResponseEncPrivateKey() == null
            || tx.getResponseEncPublicKey() == null) {
            LOG.warnf("Failing tx %s: missing encryption material: %s", txId, VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY);
            throw new VpVerificationException(VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY,
                "transaction " + txId + " has no response-encryption key material");
        }
        // The wallet can only POST where we tell it to, so what we publish must be the
        // transaction's own endpoint, not the base. Publishing the base made every real
        // presentation 404 — no verifier code ran, so nothing was logged either.
        return requestBuilder.build(tx, clientId, responseUri + "/response/" + tx.getId(),
            REQUEST_OBJECT_TTL_SECONDS);
    }

    /**
     * Entry point for {@code response_mode=direct_post.jwt}: opens the envelope, then hands the
     * contents to the unchanged {@link #processWalletResponse(String, String, String, String)}.
     *
     * <p>A body that cannot be opened fails the whole transaction with
     * {@link VpErrorCode#RESPONSE_DECRYPTION_FAILED} — including a clear-text {@code vp_token},
     * which is how the switch to encrypted responses is enforced rather than merely announced.
     *
     * <p>Fails closed with {@link VpErrorCode#TRANSACTION_MISSING_ENCRYPTION_KEY} when the
     * transaction has no key material, mirroring the guard in {@link #getRequestObject(String)}.
     * {@link PresentationTransaction#responseEncryptionKey()} throws an unchecked
     * {@code IllegalStateException} on a null key, which must never surface as an unhandled crash
     * on the wallet-facing HTTP thread.
     *
     * <p>No-op (silent return) on an absent or non-PENDING transaction, same entry guard as
     * {@link #processWalletResponse(String, String, String, String)} and {@link #failFromWallet}:
     * without it, a second POST carrying an undecryptable body could reach a transaction that
     * already went COMPLETED (before the browser consumed it via {@code complete/{tx}}) and flip
     * a successful login to FAILED via {@link #failTransaction}, which unconditionally overwrites
     * status.
     */
    public void processEncryptedWalletResponse(String txId, String compactJwe, String format) {
        PresentationTransaction tx = store.get(txId);
        if (tx == null || tx.getStatus() != TransactionStatus.PENDING) {
            // note: this guard is not atomic; see Javadoc for concurrency limitation.
            return;
        }
        if (tx.getResponseEncKid() == null || tx.getResponseEncPrivateKey() == null
            || tx.getResponseEncPublicKey() == null) {
            LOG.warnf("Failing tx %s: missing encryption material: %s", txId, VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY);
            failTransaction(tx, VpErrorCode.TRANSACTION_MISSING_ENCRYPTION_KEY);
            return;
        }
        EncryptedResponse.WalletResponse response;
        try {
            response = EncryptedResponse.decrypt(compactJwe, tx.responseEncryptionKey().privateKey());
        } catch (Exception e) {
            // Catches VpVerificationException from EncryptedResponse.decrypt (the JWE could not be
            // opened) AND the unchecked IllegalStateException that ResponseEncryptionKey.restore
            // throws when responseEncryptionKey() above hits corrupt (non-null but malformed) key
            // material in the store. Both are "the response could not be read" from the wallet's
            // perspective, and neither may escape uncaught onto this wallet-facing HTTP thread.
            LOG.warnf("Failing tx %s on wallet response decryption: %s", txId, VpErrorCode.RESPONSE_DECRYPTION_FAILED);
            failTransaction(tx, VpErrorCode.RESPONSE_DECRYPTION_FAILED);
            return;
        }
        if (response.error() != null && !response.error().isBlank()) {
            failFromWallet(txId, response.error());
            return;
        }
        processWalletResponse(txId, response.vpToken(), response.state(), format);
    }

    /**
     * Handles the wallet's {@code direct_post} response: validates {@code state}, parses the 1.0
     * {@code vp_token} envelope against the DCQL, then verifies <b>every</b> presentation against
     * the query its key designates.
     *
     * <p><b>Two failure regimes, depending on what failed:</b></p>
     * <ul>
     *   <li>{@link VpErrorCode#CREDENTIAL_EXPIRED}: the presentation is discarded with a log entry
     *       and the others carry on. Expiry is an expected lifecycle event — it is exactly the
     *       "my card expired, so I am also presenting my PID" case that renewal has to serve;</li>
     *   <li>any other failure (trust, signature, disclosures, holder binding, conformance): the
     *       whole transaction fails. That is not lifecycle noise but a sign of attack, and
     *       accepting the rest of a response that contains a forgery would mean ignoring what we
     *       did not understand.</li>
     * </ul>
     *
     * <p>Idempotence and the TOCTOU window: unchanged, see above.</p>
     */
    public void processWalletResponse(String txId, String vpToken, String state, String format) {
        PresentationTransaction tx = store.get(txId);
        if (tx == null || tx.getStatus() != TransactionStatus.PENDING) {
            // note: this guard is not atomic; see Javadoc for concurrency limitation.
            return;
        }
        if (!tx.getState().equals(state)) {
            failTransaction(tx, VpErrorCode.PARSING_ERROR);
            return;
        }
        VpVerifier verifier = verifiers.get(format);
        if (verifier == null) {
            failTransaction(tx, VpErrorCode.PARSING_ERROR);
            return;
        }

        DcqlQuery query = DcqlQuery.fromJson(tx.getDcqlQueryJson());
        VpTokenResponse response;
        try {
            response = VpTokenResponse.parse(vpToken, query);
        } catch (VpVerificationException e) {
            LOG.warnf("Refusing the vp_token of tx %s: %s", txId, e.getMessage());
            failTransaction(tx, e.getCode());
            return;
        }

        List<VerifiedPresentation> verified = new ArrayList<>();
        boolean discardedAsExpired = false;
        for (Map.Entry<String, String> entry : response.presentations().entrySet()) {
            PresentationRequestContext context = new PresentationRequestContext(
                tx.getNonce(), clientId, query, trustPolicy, entry.getKey());
            try {
                verified.add(verifier.verify(entry.getValue(), context));
            } catch (VpVerificationException e) {
                if (e.getCode() == VpErrorCode.CREDENTIAL_EXPIRED) {
                    discardedAsExpired = true;
                    LOG.infof("Discarding the presentation returned under key '%s' of tx %s: %s",
                        entry.getKey(), txId, e.getMessage());
                    continue;
                }
                LOG.warnf("Failing tx %s on the presentation returned under key '%s': %s",
                    txId, entry.getKey(), e.getMessage());
                failTransaction(tx, e.getCode());
                return;
            }
        }

        if (verified.isEmpty()) {
            // No usable presentation: refuse, never guess an identity. The code distinguishes
            // "everything presented had expired" from "nothing usable was presented at all" —
            // two very different situations from an operator's seat.
            failTransaction(tx, discardedAsExpired
                ? VpErrorCode.CREDENTIAL_EXPIRED : VpErrorCode.QUERY_NOT_SATISFIED);
            return;
        }

        tx.setStatus(TransactionStatus.COMPLETED);
        tx.setPresentations(verified);
        store.replace(tx, 0);
    }

    /**
     * Records an error posted by the wallet itself (e.g. {@code access_denied}), rather
     * than a failed verification. A no-op if the transaction is absent or not PENDING.
     */
    public void failFromWallet(String txId, String walletErrorCode) {
        PresentationTransaction tx = store.get(txId);
        if (tx == null || tx.getStatus() != TransactionStatus.PENDING) {
            return;
        }
        failTransaction(tx, VpErrorCode.WALLET_ERROR);
    }

    /**
     * Reads the transaction for terminal-state polling: PENDING is returned without
     * being consumed (the caller may poll again); COMPLETED/FAILED/EXPIRED is consumed
     * atomically and returned, so a second poll for the same id returns {@code null}.
     * Returns {@code null} if the transaction is absent.
     */
    public PresentationTransaction pollAndConsumeIfTerminal(String txId) {
        PresentationTransaction tx = store.get(txId);
        if (tx == null) {
            return null;
        }
        if (tx.getStatus() == TransactionStatus.PENDING) {
            return tx;
        }
        return store.consume(txId);
    }

    /**
     * Non-consuming read of a transaction, regardless of its status. Unlike
     * {@link #pollAndConsumeIfTerminal(String)}, this never removes a terminal
     * transaction from the store — it is meant for a caller (e.g. a status
     * endpoint) that only wants to observe the current state without taking part
     * in the single-use terminal-consumption protocol. Returns {@code null} if
     * the transaction is absent (never created, expired, or already consumed).
     */
    public PresentationTransaction peek(String txId) {
        return store.get(txId);
    }

    private void failTransaction(PresentationTransaction tx, VpErrorCode code) {
        tx.setStatus(TransactionStatus.FAILED);
        tx.setErrorCode(code.name());
        store.replace(tx, 0);
    }

    private static String randomToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return B64URL_NOPAD.encodeToString(bytes);
    }
}
