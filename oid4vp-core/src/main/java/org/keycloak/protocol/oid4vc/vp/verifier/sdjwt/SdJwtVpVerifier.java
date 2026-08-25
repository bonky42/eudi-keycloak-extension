package org.keycloak.protocol.oid4vc.vp.verifier.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;
import org.keycloak.protocol.oid4vc.vp.trust.IssuerDecision;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;
import org.keycloak.protocol.oid4vc.vp.verifier.EcJose;
import org.keycloak.protocol.oid4vc.vp.verifier.PresentationRequestContext;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerifier;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies a {@code dc+sd-jwt} (SD-JWT VC) vp_token through the whole chain: parsing, x5c trust,
 * issuer signature, disclosure consistency, holder binding (KB-JWT), credential temporal validity,
 * and conformance to the DCQL query — in that order, each link raising a distinct
 * {@link VpErrorCode}.
 */
public final class SdJwtVpVerifier implements VpVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_NOPAD = Base64.getUrlEncoder().withoutPadding();

    private static final Set<String> RESERVED_PAYLOAD_CLAIMS =
        Set.of("_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "nbf", "vct");

    private static final long KB_IAT_SKEW_SECONDS = 300;
    private static final long CREDENTIAL_TIME_SKEW_SECONDS = 60;

    private final Clock clock;

    public SdJwtVpVerifier() {
        this(Clock.systemUTC());
    }

    public SdJwtVpVerifier(Clock clock) {
        this.clock = clock;
    }

    @Override
    public VerifiedPresentation verify(String vpToken, PresentationRequestContext context)
        throws VpVerificationException {

        // Link 1: parsing, and the KB-JWT must be there
        SdJwtParts parts = SdJwtParts.parse(vpToken);
        if (parts.kbJwt() == null) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "holder binding required");
        }

        // Link 2: x5c chain -> trust anchor
        List<X509Certificate> x5cChain = parseX5cChain(parts.issuerHeader());
        X509Certificate trustAnchor;
        try {
            trustAnchor = context.getTrustPolicy().getAnchors().validateChain(x5cChain);
        } catch (GeneralSecurityException e) {
            // Name the chain that was actually presented. Without it the operator learns only that
            // nothing matched, and has no way to discover WHICH issuer showed up — so no way to
            // decide whether to add an anchor or to refuse the credential. These are the issuer
            // certificate's own DNs: metadata about the issuer, never holder data.
            throw new VpVerificationException(VpErrorCode.UNTRUSTED_ISSUER,
                "x5c chain does not validate against trust store: " + e.getMessage()
                    + "; presented chain: " + describeChain(x5cChain));
        }
        X509Certificate leaf = x5cChain.get(0);

        // Link 3: ES256 signature over the issuer JWT, by the leaf certificate's key
        verifyEs256(parts.issuerJwt(), leaf.getPublicKey(),
            VpErrorCode.INVALID_SIGNATURE, "issuer JWT signature invalid");

        // Link 3a: is this anchor entitled to sign THIS type of card?
        //
        // Placed AFTER link 3, even though the anchor is known from link 2 on: `vct` lives in the
        // issuer JWT payload, which only link 3 authenticates. Basing a security decision on a
        // field that is not yet authenticated is a bad habit even where it can be shown not to be
        // exploitable; moving one line down costs nothing.
        String vct = textOrNull(parts.issuerPayload(), "vct");
        if (context.getTrustPolicy().getAuthorization().decide(vct, trustAnchor)
            == IssuerDecision.REFUSED) {
            throw new VpVerificationException(VpErrorCode.ISSUER_NOT_AUTHORIZED,
                "issuer anchor is trusted but not entitled to sign vct=" + vct);
        }

        // Link 4: disclosures consistent with _sd, and no name disclosed twice
        Map<String, Object> disclosedClaims = verifyDisclosures(parts);

        // Link 5: KB-JWT (signature, nonce, aud, sd_hash, freshness)
        verifyKeyBinding(parts, context);

        // Link 6: temporal validity of the credential (issuer payload)
        // 6 BEFORE 7 IS DELIBERATE: an expired presentation is rejected (CREDENTIAL_EXPIRED, the
        // "lifecycle" regime) before its conformance to the query is even examined — including
        // when it was filed under the wrong key. Swapping them would surface QUERY_NOT_SATISFIED
        // (the "whole transaction is fatal" regime, spec section 3) for a card that has merely
        // expired. Do NOT "fix" this order.
        verifyTemporalValidity(parts.issuerPayload());

        // Link 7: conformance to the query DESIGNATED BY THE RESPONSE KEY
        // (`vct` was read at link 3a, once the payload was authenticated)
        verifyQueryConformance(vct, disclosedClaims, context);

        return buildResult(parts.issuerPayload(), disclosedClaims, trustAnchor, vct);
    }

    @Override
    public void close() {
        // stateless: nothing to release
    }

    // ---- Link 2 -------------------------------------------------------

    /**
     * Renders the presented certificate chain as {@code subject <- issuer} pairs, for the trust
     * failure message. Only the certificates' own distinguished names — no key material, no
     * credential content, nothing about the holder.
     */
    private static String describeChain(List<X509Certificate> chain) {
        StringBuilder rendered = new StringBuilder();
        for (X509Certificate certificate : chain) {
            if (rendered.length() > 0) {
                rendered.append(" | ");
            }
            rendered.append('[').append(certificate.getSubjectX500Principal().getName())
                .append(" <- ").append(certificate.getIssuerX500Principal().getName()).append(']');
        }
        return rendered.toString();
    }

    private List<X509Certificate> parseX5cChain(JsonNode header) throws VpVerificationException {
        JsonNode x5c = header.get("x5c");
        if (x5c == null || !x5c.isArray() || x5c.isEmpty()) {
            throw new VpVerificationException(VpErrorCode.UNTRUSTED_ISSUER, "missing or empty x5c header");
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> chain = new ArrayList<>();
            for (JsonNode certNode : x5c) {
                byte[] der = Base64.getDecoder().decode(certNode.asText());
                chain.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
            return chain;
        } catch (Exception e) {
            throw new VpVerificationException(VpErrorCode.UNTRUSTED_ISSUER,
                "failed to parse x5c chain: " + e.getMessage());
        }
    }

    // ---- Link 3, and the KB-JWT signature (link 5) ---------------------

    private void verifyEs256(String jwt, PublicKey key, VpErrorCode failureCode, String failureMessage)
        throws VpVerificationException {
        String[] segments = jwt.split("\\.", -1);
        if (segments.length != 3) {
            throw new VpVerificationException(failureCode, failureMessage + ": malformed JWT (expected 3 segments)");
        }
        try {
            String signingInput = segments[0] + "." + segments[1];
            if (!EcJose.verify(key, signingInput, segments[2])) {
                throw new VpVerificationException(failureCode, failureMessage);
            }
        } catch (VpVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VpVerificationException(failureCode, failureMessage + ": " + e.getMessage());
        }
    }

    // ---- Link 4 ---------------------------------------------------------

    private Map<String, Object> verifyDisclosures(SdJwtParts parts) throws VpVerificationException {
        Set<String> sdDigests = new HashSet<>();
        JsonNode sdNode = parts.issuerPayload().get("_sd");
        if (sdNode != null && sdNode.isArray()) {
            for (JsonNode digest : sdNode) {
                sdDigests.add(digest.asText());
            }
        }

        Map<String, Object> claims = new LinkedHashMap<>();
        Set<String> seenNames = new HashSet<>();
        for (String disclosure : parts.disclosures()) {
            String digest = sha256B64Url(disclosure);
            if (!sdDigests.contains(digest)) {
                throw new VpVerificationException(VpErrorCode.DISCLOSURE_MISMATCH,
                    "disclosure digest not present in _sd");
            }

            JsonNode array;
            try {
                array = MAPPER.readTree(B64URL.decode(disclosure));
            } catch (Exception e) {
                throw new VpVerificationException(VpErrorCode.DISCLOSURE_MISMATCH,
                    "malformed disclosure: " + e.getMessage());
            }
            if (!array.isArray() || array.size() != 3) {
                throw new VpVerificationException(VpErrorCode.DISCLOSURE_MISMATCH,
                    "disclosure must decode to [salt, name, value]");
            }

            String name = array.get(1).asText();
            if (!seenNames.add(name)) {
                throw new VpVerificationException(VpErrorCode.DISCLOSURE_MISMATCH,
                    "claim name disclosed more than once: " + name);
            }
            claims.put(name, jsonNodeToValue(array.get(2)));
        }
        return claims;
    }

    // ---- Link 5 -----------------------------------------------------------

    private void verifyKeyBinding(SdJwtParts parts, PresentationRequestContext context)
        throws VpVerificationException {
        String kbJwt = parts.kbJwt();
        String[] segments = kbJwt.split("\\.", -1);
        if (segments.length != 3) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING,
                "kb-jwt must have exactly 3 segments");
        }

        JsonNode kbHeader = decodeJsonOrKbError(segments[0], "kb-jwt header");
        JsonNode kbPayload = decodeJsonOrKbError(segments[1], "kb-jwt payload");

        String typ = textOrNull(kbHeader, "typ");
        if (!"kb+jwt".equals(typ)) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "kb-jwt typ must be \"kb+jwt\"");
        }

        PublicKey holderKey = extractHolderKey(parts.issuerPayload());
        verifyEs256(kbJwt, holderKey, VpErrorCode.INVALID_KEY_BINDING, "kb-jwt signature invalid");

        if (!Objects.equals(context.getNonce(), textOrNull(kbPayload, "nonce"))) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "kb-jwt nonce mismatch");
        }
        if (!Objects.equals(context.getClientId(), textOrNull(kbPayload, "aud"))) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "kb-jwt aud mismatch");
        }

        String expectedSdHash = sha256B64Url(parts.presentationWithoutKb());
        if (!Objects.equals(expectedSdHash, textOrNull(kbPayload, "sd_hash"))) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "kb-jwt sd_hash mismatch");
        }

        JsonNode iatNode = kbPayload.get("iat");
        if (iatNode == null || !iatNode.isNumber()) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "kb-jwt missing iat");
        }
        long now = clock.instant().getEpochSecond();
        if (Math.abs(now - iatNode.asLong()) > KB_IAT_SKEW_SECONDS) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING,
                "kb-jwt iat outside the +/-" + KB_IAT_SKEW_SECONDS + "s freshness window");
        }
    }

    private JsonNode decodeJsonOrKbError(String segment, String description) throws VpVerificationException {
        try {
            return MAPPER.readTree(B64URL.decode(segment));
        } catch (Exception e) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING,
                "failed to decode " + description + ": " + e.getMessage());
        }
    }

    private PublicKey extractHolderKey(JsonNode issuerPayload) throws VpVerificationException {
        JsonNode cnf = issuerPayload.get("cnf");
        JsonNode jwk = cnf != null ? cnf.get("jwk") : null;
        if (jwk == null) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "issuer payload missing cnf.jwk");
        }
        String crv = textOrNull(jwk, "crv");
        if (!"P-256".equals(crv)) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING, "unsupported cnf.jwk crv: " + crv);
        }
        try {
            BigInteger x = new BigInteger(1, B64URL.decode(jwk.get("x").asText()));
            BigInteger y = new BigInteger(1, B64URL.decode(jwk.get("y").asText()));

            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);

            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecParameterSpec));
        } catch (Exception e) {
            throw new VpVerificationException(VpErrorCode.INVALID_KEY_BINDING,
                "failed to reconstruct holder public key from cnf.jwk: " + e.getMessage());
        }
    }

    // ---- Link 6 -------------------------------------------------------------

    private void verifyTemporalValidity(JsonNode issuerPayload) throws VpVerificationException {
        long now = clock.instant().getEpochSecond();

        JsonNode exp = issuerPayload.get("exp");
        if (exp != null && exp.isNumber() && now > exp.asLong()) {
            throw new VpVerificationException(VpErrorCode.CREDENTIAL_EXPIRED, "credential expired");
        }
        JsonNode nbf = issuerPayload.get("nbf");
        if (nbf != null && nbf.isNumber() && now < nbf.asLong() - CREDENTIAL_TIME_SKEW_SECONDS) {
            throw new VpVerificationException(VpErrorCode.CREDENTIAL_NOT_YET_VALID, "credential not yet valid (nbf)");
        }
        JsonNode iat = issuerPayload.get("iat");
        if (iat != null && iat.isNumber() && now < iat.asLong() - CREDENTIAL_TIME_SKEW_SECONDS) {
            throw new VpVerificationException(VpErrorCode.CREDENTIAL_NOT_YET_VALID, "credential not yet valid (iat)");
        }
    }

    // ---- Link 7 ---------------------------------------------------------------

    /**
     * Checks that the presentation satisfies <b>the query the wallet filed it under</b> — not
     * "any query in the DCQL", which is what this did while only one query was ever sent at a time.
     *
     * <p>This is the hardening that makes the response key harmless: it does not choose an identity
     * regime, it only chooses which contract has to be honoured. A PID filed under {@code own}
     * fails here, because the {@code own} query does not ask for that {@code vct}.</p>
     */
    private void verifyQueryConformance(String vct, Map<String, Object> disclosedClaims,
                                         PresentationRequestContext context)
        throws VpVerificationException {

        String queryId = context.getCredentialQueryId();
        DcqlQuery.CredentialQuery query = context.getDcqlQuery() == null
            ? null : context.getDcqlQuery().credentialById(queryId);
        if (query == null) {
            throw new VpVerificationException(VpErrorCode.QUERY_NOT_SATISFIED,
                "no credential query with id '" + queryId + "' in this request");
        }

        List<String> vctValues = query.getMeta() != null ? query.getMeta().getVctValues() : null;
        if (vctValues == null || !vctValues.contains(vct)) {
            throw new VpVerificationException(VpErrorCode.QUERY_NOT_SATISFIED,
                "presentation returned under key '" + queryId + "' carries vct=" + vct
                    + ", which that credential query does not request");
        }
        if (!allClaimsDisclosed(query.getClaims(), disclosedClaims)) {
            throw new VpVerificationException(VpErrorCode.QUERY_NOT_SATISFIED,
                "presentation returned under key '" + queryId
                    + "' does not disclose every claim that credential query requests");
        }
    }

    private boolean allClaimsDisclosed(List<DcqlQuery.ClaimQuery> claimQueries, Map<String, Object> disclosedClaims) {
        if (claimQueries == null) {
            return true;
        }
        for (DcqlQuery.ClaimQuery claimQuery : claimQueries) {
            List<String> path = claimQuery.getPath();
            if (path == null || path.isEmpty() || !disclosedClaims.containsKey(path.get(0))) {
                return false;
            }
        }
        return true;
    }

    // ---- Result -----------------------------------------------------------------

    private VerifiedPresentation buildResult(JsonNode issuerPayload, Map<String, Object> disclosedClaims,
                                              X509Certificate trustAnchor, String vct) {
        Map<String, Object> claims = new LinkedHashMap<>(disclosedClaims);
        Iterator<Map.Entry<String, JsonNode>> fields = issuerPayload.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            if (!RESERVED_PAYLOAD_CLAIMS.contains(field.getKey())) {
                claims.putIfAbsent(field.getKey(), jsonNodeToValue(field.getValue()));
            }
        }
        String issuer = textOrNull(issuerPayload, "iss");
        String trustAnchorSubject = trustAnchor.getSubjectX500Principal().getName();
        JsonNode exp = issuerPayload.get("exp");
        Long expiresAt = exp != null && exp.isNumber() ? exp.asLong() : null;
        return new VerifiedPresentation(claims, issuer, trustAnchorSubject, vct, expiresAt);
    }

    // ---- Helpers --------------------------------------------------------------------

    private static String sha256B64Url(String asciiInput) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(asciiInput.getBytes(StandardCharsets.US_ASCII));
            return B64URL_NOPAD.encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && !value.isNull() ? value.asText() : null;
    }

    private static Object jsonNodeToValue(JsonNode node) {
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        if (node.isIntegralNumber()) {
            return node.longValue();
        }
        if (node.isFloatingPointNumber()) {
            return node.doubleValue();
        }
        if (node.isNull() || node.isMissingNode()) {
            return null;
        }
        return MAPPER.convertValue(node, Object.class);
    }
}
