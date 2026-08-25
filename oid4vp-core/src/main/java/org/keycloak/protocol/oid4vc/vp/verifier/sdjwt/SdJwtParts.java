package org.keycloak.protocol.oid4vc.vp.verifier.sdjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.protocol.oid4vc.vp.verifier.VpErrorCode;
import org.keycloak.protocol.oid4vc.vp.verifier.VpVerificationException;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Splits a {@code <issuer-jwt>~<disclosure>*~[<kb-jwt>]} presentation and decodes each piece.
 *
 * <p>Expected format (SD-JWT VC, IETF draft): the issuer JWT, followed by zero or more disclosures,
 * each terminated by {@code ~}. If the presentation ends on {@code ~} there is no KB-JWT (an
 * "issuer-only" presentation); otherwise the last segment after the last {@code ~} is the
 * KB-JWT.</p>
 */
public final class SdJwtParts {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String issuerJwt;
    private final JsonNode issuerHeader;
    private final JsonNode issuerPayload;
    private final List<String> disclosures;
    private final String kbJwt;
    private final String presentationWithoutKb;

    private SdJwtParts(String issuerJwt, JsonNode issuerHeader, JsonNode issuerPayload,
                        List<String> disclosures, String kbJwt, String presentationWithoutKb) {
        this.issuerJwt = issuerJwt;
        this.issuerHeader = issuerHeader;
        this.issuerPayload = issuerPayload;
        this.disclosures = disclosures;
        this.kbJwt = kbJwt;
        this.presentationWithoutKb = presentationWithoutKb;
    }

    public static SdJwtParts parse(String vpToken) throws VpVerificationException {
        if (vpToken == null || !vpToken.contains("~")) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "vp_token must contain at least one '~' separator");
        }

        String[] segments = vpToken.split("~", -1);
        // segments[0] = issuer-jwt, segments[1..n-2] = disclosures, segments[n-1] = kb-jwt or "" (trailing ~)

        String issuerJwt = segments[0];
        String lastSegment = segments[segments.length - 1];
        boolean hasKbJwt = !lastSegment.isEmpty();

        // In both cases (trailing kb-jwt, or trailing empty segment from "~") the
        // disclosures are the segments strictly between the issuer-jwt and the last one.
        List<String> disclosures = List.of(segments).subList(1, segments.length - 1);
        String kbJwt = hasKbJwt ? lastSegment : null;

        String[] issuerJwtSegments = issuerJwt.split("\\.", -1);
        if (issuerJwtSegments.length != 3) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "issuer JWT must have exactly 3 base64url segments, found " + issuerJwtSegments.length);
        }
        JsonNode issuerHeader = decodeJsonSegment(issuerJwtSegments[0], "issuer JWT header");
        JsonNode issuerPayload = decodeJsonSegment(issuerJwtSegments[1], "issuer JWT payload");

        for (String disclosure : disclosures) {
            validateDisclosure(disclosure);
        }

        StringBuilder presentationWithoutKb = new StringBuilder(issuerJwt).append('~');
        for (String disclosure : disclosures) {
            presentationWithoutKb.append(disclosure).append('~');
        }

        return new SdJwtParts(issuerJwt, issuerHeader, issuerPayload,
            Collections.unmodifiableList(disclosures), kbJwt, presentationWithoutKb.toString());
    }

    private static JsonNode decodeJsonSegment(String base64UrlSegment, String description) throws VpVerificationException {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(base64UrlSegment);
            return MAPPER.readTree(decoded);
        } catch (Exception e) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "Failed to decode " + description + ": " + e.getMessage());
        }
    }

    private static void validateDisclosure(String disclosure) throws VpVerificationException {
        JsonNode node = decodeJsonSegment(disclosure, "disclosure");
        if (!node.isArray()) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "Disclosure must decode to a JSON array, got: " + node.getNodeType());
        }
    }

    public String issuerJwt() {
        return issuerJwt;
    }

    public JsonNode issuerHeader() {
        return issuerHeader;
    }

    public JsonNode issuerPayload() {
        return issuerPayload;
    }

    public List<String> disclosures() {
        return disclosures;
    }

    public String kbJwt() {
        return kbJwt;
    }

    public String presentationWithoutKb() {
        return presentationWithoutKb;
    }
}
