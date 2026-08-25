package org.keycloak.protocol.oid4vc.vp.login.protocol;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * One verified presentation, as it travels from the identity provider to the token mapper in the
 * {@link VerifiedClaimsNotes#PRESENTATIONS} session note.
 *
 * <p>An array note rather than six flat ones: a login can rest on two presentations, and every
 * assertion must stay attributed to the card carrying it. The flat notes remain, but now explicitly
 * describe the presentation that founded the identity — which is what their readers expect,
 * including the future conditional authenticator that reads {@code oid4vp.vc.vct}.</p>
 *
 * <p><b>No expiry here.</b> A card's {@code expiresAt} feeds the re-offer decision alone and must
 * not come near the token: it travels separately, in {@link VerifiedClaimsNotes#CTX_CARDS}, outside
 * {@link VerifiedClaimsNotes#ALL}.</p>
 */
public record PresentationNote(String issuer, String vct, String format, String trustAnchor,
                                String verifiedAt, Map<String, Object> claims) {

    private static final Logger LOG = Logger.getLogger(PresentationNote.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<PresentationNote>> LIST_TYPE = new TypeReference<>() {
    };

    public static String toJson(List<PresentationNote> notes) {
        try {
            return MAPPER.writeValueAsString(notes);
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize presentation notes", e);
        }
    }

    /** Never {@code null}, and never holding a {@code null} element. An absent or unreadable note,
     *  or a JSON array containing a literal {@code null} — Jackson deserialises {@code [null,{...}]}
     *  into a list with a {@code null} element WITHOUT throwing — yields an empty or shortened list,
     *  never an NPE reaching the caller. Filtered here at the boundary, to protect every future
     *  consumer and not just today's mapper. */
    public static List<PresentationNote> fromJson(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            List<PresentationNote> parsed = MAPPER.readValue(json, LIST_TYPE);
            if (parsed == null) {
                return List.of();
            }
            return parsed.stream().filter(Objects::nonNull).collect(Collectors.toUnmodifiableList());
        } catch (Exception e) {
            LOG.warnf(e, "Unreadable %s session note; emitting no verified_claims",
                VerifiedClaimsNotes.PRESENTATIONS);
            return List.of();
        }
    }
}
