package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.keycloak.protocol.oid4vc.vp.model.DcqlQuery;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The claim names a DCQL query asks for, so the login page can name them before the holder decides.
 *
 * <p>OpenID4VP 1.0 section 6.2 asks the Verifier to show the End-User the purpose and context of a
 * request before sending it, and defines no protocol field for doing so — a Credential Set Query
 * carries {@code options} and {@code required} and nothing else. That leaves the verifier's own page
 * as the only place it can happen.</p>
 *
 * <p>Derived from the query actually being sent, never from a list somebody maintains: a page that
 * names what it asks for must not be able to drift from what it asks for.</p>
 *
 * <p>Only the first path segment names a claim. A request for {@code ["address","locality"]} is
 * shown as {@code address}, because naming the path into a claim tells a holder nothing they can act
 * on.</p>
 */
public final class RequestedClaims {

    private RequestedClaims() {
    }

    /** Every claim the query names, in encounter order, without duplicates. Never {@code null}. */
    public static List<String> of(DcqlQuery query) {
        if (query == null || query.getCredentials() == null) {
            return List.of();
        }
        Set<String> names = new LinkedHashSet<>();
        for (DcqlQuery.CredentialQuery credential : query.getCredentials()) {
            if (credential == null || credential.getClaims() == null) {
                continue;
            }
            for (DcqlQuery.ClaimQuery claim : credential.getClaims()) {
                if (claim == null || claim.getPath() == null || claim.getPath().isEmpty()) {
                    continue;
                }
                String first = claim.getPath().get(0);
                // A blank entry would render as a bullet with no text, which reads as a defect
                // rather than as an absence.
                if (first != null && !first.isBlank()) {
                    names.add(first.trim());
                }
            }
        }
        return List.copyOf(names);
    }
}
