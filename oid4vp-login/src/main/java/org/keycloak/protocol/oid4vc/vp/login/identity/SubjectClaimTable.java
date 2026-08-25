package org.keycloak.protocol.oid4vc.vp.login.identity;

import org.keycloak.protocol.oid4vc.vp.login.protocol.VctTable;

/**
 * Which claim carries the subject, for a given credential type.
 *
 * <p>This table declares THAT and nothing else. It never decides the identity regime: the verbatim
 * regime stays derived from {@code ownVct} and is not configurable per row — it is safe only
 * because WE wrote the value at issuance, and opening it to a third-party type would let an issuer
 * name an account directly.</p>
 *
 * <p>A {@code vct} absent from the table falls back to the global {@code subjectClaim}, so older
 * realms keep working untouched.</p>
 */
public final class SubjectClaimTable {

    private SubjectClaimTable() {
    }

    public static String claimFor(String table, String vct, String fallback) {
        String declared = vct == null ? null : VctTable.parse(table).get(vct);
        return declared != null ? declared : fallback;
    }
}
