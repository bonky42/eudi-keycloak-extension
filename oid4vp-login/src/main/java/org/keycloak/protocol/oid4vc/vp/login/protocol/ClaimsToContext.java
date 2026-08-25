package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.protocol.oid4vc.vp.model.VerifiedPresentation;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps a {@link VerifiedPresentation} — the claims the OID4VP engine verified — onto a Keycloak
 * {@link BrokeredIdentityContext}. A pure class: no dependency on the Keycloak runtime beyond the
 * context POJO, and no side effect outside the context passed in.
 */
public final class ClaimsToContext {

    /** The user attribute carrying the federated identifier, read by the ISSUANCE mapper
     *  ({@code oid4vc-subject-id-mapper}) to populate the {@code sub} of the card this Keycloak
     *  issues itself. Exposed as a constant so the identity provider (writer), that mapper
     *  (reader) and the integration tests can never drift apart on its name. */
    public static final String FEDID_ATTRIBUTE = "oid4vp.fedid";

    private ClaimsToContext() {
    }

    /**
     * Merges the claims of every verified presentation, <b>the PID winning on collision</b>: it is
     * the source of the identity checks, and our own card has no authority to contradict a verified
     * civil status.
     *
     * <p>How far this rule actually reaches: the "both cards" case can never arise at account
     * creation, since an unknown holder does not have our card yet. The two only coexist on an
     * account that ALREADY exists, where attributes are not refreshed today. The rule is therefore
     * right as a principle and has no practical effect — it is written now so that the day refresh
     * arrives, precedence is already the correct way round.</p>
     */
    public static Map<String, Object> mergedClaims(List<VerifiedPresentation> presentations,
                                                    String ownVct) {
        Map<String, Object> merged = new LinkedHashMap<>();
        // Our own cards first, everything else second, so the second overwrite the first.
        for (VerifiedPresentation presentation : presentations) {
            if (ownVct != null && ownVct.equals(presentation.getVct())) {
                merged.putAll(presentation.getClaims());
            }
        }
        for (VerifiedPresentation presentation : presentations) {
            if (ownVct == null || !ownVct.equals(presentation.getVct())) {
                merged.putAll(presentation.getClaims());
            }
        }
        return merged;
    }

    /**
     * Sets on the context: the username (derived from matchingClaim when present, otherwise from
     * issuer+subjectClaim, or issuer+"unknown" when that claim is missing too), and every verified
     * claim as an "oid4vp.&lt;name&gt;" attribute. The username is cosmetic — the federated identity
     * rests on {@link #brokeredIdentityId} — so this method must never fail.
     *
     * <p>The claims arrive already merged by {@link #mergedClaims}: {@code vp} now designates only
     * the presentation that founded the identity.</p>
     *
     * @param vp            the presentation that founded the identity, and the source of the
     *                      issuer/vct set on the context
     * @param claims        the merged claims of every presentation in this login
     * @param ctx           the federated identity context to populate
     * @param matchingClaim the name of the claim to use as an identifier ("email" for instance),
     *                      or null
     * @param subjectClaim  the name of the configured stable subject claim, used as the username
     *                      fallback when {@code matchingClaim} is absent or null. It must stay
     *                      consistent with {@link #brokeredIdentityId}: otherwise two holders with
     *                      no "sub" but distinct values of that claim would both end up named
     *                      "issuer:unknown" and collide.
     */
    public static void apply(VerifiedPresentation vp, Map<String, Object> claims, BrokeredIdentityContext ctx,
                              String matchingClaim, String subjectClaim) {
        if (matchingClaim != null && claims.containsKey(matchingClaim)) {
            String value = String.valueOf(claims.get(matchingClaim));
            ctx.setUsername(value);
            if (value.contains("@")) {
                ctx.setEmail(value);
            }
        } else {
            Object subject = subjectClaim != null ? claims.get(subjectClaim) : null;
            String subjectValue = subject != null ? String.valueOf(subject) : "unknown";
            ctx.setUsername(vp.getIssuer() + ":" + subjectValue);
        }

        // Fill the standard profile (first/last name) from the usual PID claims, so that user
        // creation at first broker login has the fields Keycloak's user profile requires —
        // otherwise the "Review Profile" step in "missing" mode would block a non-interactive
        // flow. The claims stay exposed as "oid4vp.*" attributes below as well.
        if (claims.get("given_name") != null) {
            ctx.setFirstName(String.valueOf(claims.get("given_name")));
        }
        if (claims.get("family_name") != null) {
            ctx.setLastName(String.valueOf(claims.get("family_name")));
        }

        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            setIfPresent(ctx, "oid4vp." + entry.getKey(), entry.getValue());
        }

        setIfPresent(ctx, "oid4vp.issuer", vp.getIssuer());
        setIfPresent(ctx, "oid4vp.vct", vp.getVct());
    }

    /**
     * The durable federated identifier, or {@code null} if the presentation carries no stable
     * subject. Reads {@code subjectClaim} ONLY — {@code matchingClaim} no longer influences the
     * identifier.
     *
     * <p>Two regimes, depending on the credential type:</p>
     * <ul>
     *   <li><b>Our own card</b> ({@code vct == ownVct}): the subject claim's value IS the federated
     *       identifier, taken verbatim. We wrote it ourselves at issuance, from the account's
     *       already established identifier; prefixing it a second time with our issuer would
     *       fabricate a federated link DIFFERENT from the one created at first enrolment, and would
     *       restart a first-broker-login — that is, matching by email, which this design
     *       forbids.</li>
     *   <li><b>Any other credential</b>: the ordinary rule, {@code issuer + ":" + value}.</li>
     * </ul>
     * In both regimes, no identifier is ever computed from the content of the claims — no hashing.
     * A guessed id could collide between two distinct identities and sign a wallet in to the wrong
     * account.
     *
     * @param subjectClaim the name of the configured stable subject claim, or null
     * @param ownVct       the {@code vct} of the card this Keycloak issues itself, or null when
     *                     issuance is not configured — in which case the verbatim regime can never
     *                     apply and the ordinary rule always prevails
     */
    public static String brokeredIdentityId(VerifiedPresentation vp, String subjectClaim, String ownVct) {
        if (subjectClaim == null) {
            return null;
        }
        Map<String, Object> claims = vp.getClaims();
        Object value = claims.get(subjectClaim);
        if (value == null || String.valueOf(value).isBlank()) {
            return null;
        }
        String subject = String.valueOf(value);
        if (ownVct != null && ownVct.equals(vp.getVct())) {
            return subject;
        }
        return vp.getIssuer() + ":" + subject;
    }

    /**
     * Sets {@link #FEDID_ATTRIBUTE} on the context, and only if a stable federated identifier was
     * established.
     *
     * <p>The transient path — an identity provider with {@code isTransientUsers}, or a presentation
     * with no stable subject — must produce NEITHER a card NOR an attribute: there is no durable
     * account, so there is nothing to attest. The caller MUST therefore pass the raw result of
     * {@link #brokeredIdentityId}, captured BEFORE any transient fallback, and never a variable
     * that fallback reassigned. Setting a random fallback identifier here would produce an
     * unusable card {@code sub}: exactly the kind of COMPUTED identifier this design forbids.</p>
     *
     * @param stableSubjectId the result of {@link #brokeredIdentityId}, or {@code null}
     */
    public static void applyFederatedId(BrokeredIdentityContext ctx, String stableSubjectId) {
        if (stableSubjectId != null) {
            ctx.setUserAttribute(FEDID_ATTRIBUTE, stableSubjectId);
        }
    }

    /**
     * Sets the attribute only when the value is non-null: this avoids NPEs in Keycloak's attribute
     * persistence, and never records an attribute whose value is the literal string "null".
     */
    private static void setIfPresent(BrokeredIdentityContext ctx, String name, Object value) {
        if (value != null) {
            ctx.setUserAttribute(name, String.valueOf(value));
        }
    }
}
