package org.keycloak.protocol.oid4vc.vp.login.protocol;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;

/**
 * Builder for the OIDC4IDA verified_claims structure.
 * Assembles the nested map containing verification metadata and verified claims.
 */
public final class VerifiedClaimsBuilder {

    private VerifiedClaimsBuilder() {
        // utility class
    }

    /**
     * Assemble the verified_claims OIDC4IDA object.
     * Produces a nested Map structure: { "verification": {...}, "claims": {...} }
     *
     * @param issuer       the VC issuer URI (may be null)
     * @param vct          the Verifiable Credential Type (may be null)
     * @param format       the credential format (may be null)
     * @param trustAnchor  the trust anchor (may be null)
     * @param verifiedAt   the verification timestamp (may be null)
     * @param claims       the verified claims (defensive copied)
     * @param trustFramework the trust framework (always present)
     * @return a Jackson-serializable Map with the verified_claims structure
     */
    public static Map<String, Object> build(
            String issuer,
            String vct,
            String format,
            String trustAnchor,
            String verifiedAt,
            Map<String, Object> claims,
            String trustFramework) {

        Map<String, Object> result = new LinkedHashMap<>();

        // Build verification object
        Map<String, Object> verification = new LinkedHashMap<>();
        verification.put("trust_framework", trustFramework);
        // Omit rather than emit "time": null — a literal null would misrepresent an unknown
        // verification time as an explicit claim, the same reasoning as the evidence fields below.
        if (verifiedAt != null) {
            verification.put("time", verifiedAt);
        }

        // Build evidence array with single element
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("type", "vc");
        evidence.put("method", "oid4vp");

        // Add optional evidence fields only if not null
        if (format != null) {
            evidence.put("format", format);
        }
        if (vct != null) {
            evidence.put("vct", vct);
        }
        if (issuer != null) {
            evidence.put("issuer", issuer);
        }
        if (trustAnchor != null) {
            evidence.put("trust_anchor", trustAnchor);
        }

        verification.put("evidence", Collections.singletonList(evidence));

        result.put("verification", verification);

        // Add defensive copy of claims
        result.put("claims", new LinkedHashMap<>(claims));

        return result;
    }

    /**
     * Collapses the {@code verified_claims} entries into the value to place in the token:
     * <b>the object itself</b> when there is one, which is the older shape and breaks no consumer;
     * <b>an array</b> when there are several, which OIDC4IDA explicitly allows; and {@code null}
     * when there is nothing to say, in which case the caller emits no claim at all.
     */
    public static Object collapse(List<Map<String, Object>> entries) {
        if (entries == null || entries.isEmpty()) {
            return null;
        }
        return entries.size() == 1 ? entries.get(0) : List.copyOf(entries);
    }
}
