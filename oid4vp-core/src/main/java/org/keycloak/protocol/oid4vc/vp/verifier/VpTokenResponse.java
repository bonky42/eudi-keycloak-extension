package org.keycloak.protocol.oid4vc.vp.verifier;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The OID4VP 1.0 response envelope: a JSON object whose every key is the {@code id} of a credential
 * query and whose every value is an array of presentations (section 8.1).
 *
 * <p><b>The key is declarative.</b> It comes from the wallet and says only which query the proof
 * claims to answer. It therefore selects the query to check conformance against (link 7), and is
 * NEVER used to decide an identity. A lying wallet that files a PID under the {@code own} key gains
 * nothing: conformance checking rejects it, and even if it got through, identity would be decided on
 * the {@code vct} actually carried.</p>
 *
 * <p><b>What is refused, explicitly:</b> a value that is not a JSON object (including the bare
 * string this used to accept), a key no query declares, an empty array, more than one presentation
 * under a key (section 8.1: an omitted {@code multiple} means {@code false}), and a presentation
 * that is not a string (only {@code dc+sd-jwt} is supported).</p>
 *
 * <p><b>What does NOT need checking:</b> "more presentations than declared sets". JSON object keys
 * are unique, every key must be declared, and every key carries exactly one presentation — so the
 * number of presentations is bounded by construction.</p>
 *
 * <p>A <b>missing</b> key is not an anomaly but the conformant way of saying "I do not hold that
 * card" (section 8.1); an <b>empty</b> object therefore parses without error — it is for the engine
 * to decide that no usable presentation means the login is refused.</p>
 *
 * <p><b>A limit inherited from the underlying JSON parser.</b> A {@code vp_token} whose root object
 * carries a DUPLICATED query key triggers none of the explicit refusals above: {@code
 * ObjectMapper.readTree} merges duplicate keys before this parser ever sees the document (last value
 * wins), as any RFC 8259 conformant parser may (section 4: "the names within an object SHOULD be
 * unique", not MUST). This is not covered by the "refused explicitly, never silently truncated or
 * ignored" guarantee the rest of this class offers — there is nothing left to observe once Jackson
 * has already collapsed the document.</p>
 */
public final class VpTokenResponse {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, String> presentations;

    private VpTokenResponse(Map<String, String> presentations) {
        this.presentations = Collections.unmodifiableMap(presentations);
    }

    /** The presentations, keyed by the query id that labels them, in the order they appear in the
     *  JSON. One per key at most — see the class javadoc. */
    public Map<String, String> presentations() {
        return presentations;
    }

    public static VpTokenResponse parse(String rawVpToken, DcqlQuery query)
        throws VpVerificationException {

        JsonNode root;
        try {
            root = rawVpToken == null ? null : MAPPER.readTree(rawVpToken);
        } catch (Exception e) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "vp_token is not valid JSON: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                "vp_token must be a JSON object keyed by credential query id (OID4VP 1.0 §8.1)");
        }

        Map<String, String> parsed = new LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = root.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            String key = field.getKey();

            if (query == null || query.credentialById(key) == null) {
                throw new VpVerificationException(VpErrorCode.UNKNOWN_RESPONSE_KEY,
                    "vp_token carries key '" + key + "' which no credential query declares");
            }

            JsonNode array = field.getValue();
            if (!array.isArray() || array.isEmpty()) {
                throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                    "vp_token entry '" + key + "' must be a non-empty array of presentations");
            }
            if (array.size() > 1) {
                throw new VpVerificationException(VpErrorCode.TOO_MANY_PRESENTATIONS,
                    "vp_token entry '" + key + "' carries " + array.size() + " presentations while "
                        + "the credential query does not set `multiple` (OID4VP 1.0 §8.1)");
            }
            JsonNode presentation = array.get(0);
            if (!presentation.isTextual()) {
                throw new VpVerificationException(VpErrorCode.PARSING_ERROR,
                    "vp_token entry '" + key + "' must hold a string: a dc+sd-jwt presentation is "
                        + "encoded as a string (OID4VP 1.0 Appendix B)");
            }
            parsed.put(key, presentation.textValue());
        }
        return new VpTokenResponse(parsed);
    }
}
