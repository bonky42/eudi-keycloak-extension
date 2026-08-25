package org.keycloak.protocol.oid4vc.vp.login.protocol;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads a {@code vct=value,vct=value} configuration table — the idiom shared by
 * {@code trustFrameworkByVct} and {@code subjectClaimByVct}.
 *
 * <p>A pair with no {@code =}, an empty key or an empty value is <b>ignored</b>, never guessed.
 * Detecting an entirely unusable table, and warning the operator about it, stays the caller's
 * responsibility: only the caller knows which configuration key to name.</p>
 */
public final class VctTable {

    private VctTable() {
    }

    /** The usable pairs, in the order written. Never {@code null}. Last one wins on a duplicated
     *  {@code vct} — worth knowing before relying on it for a mistyped table. */
    public static Map<String, String> parse(String table) {
        Map<String, String> parsed = new LinkedHashMap<>();
        if (table == null || table.isBlank()) {
            return parsed;
        }
        for (String pair : table.split(",")) {
            int separator = pair.indexOf('=');
            if (separator <= 0) {
                continue;
            }
            String key = pair.substring(0, separator).trim();
            String value = pair.substring(separator + 1).trim();
            if (!key.isEmpty() && !value.isEmpty()) {
                parsed.put(key, value);
            }
        }
        return parsed;
    }
}
