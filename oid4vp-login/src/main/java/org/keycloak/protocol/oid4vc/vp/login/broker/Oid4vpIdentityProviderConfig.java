package org.keycloak.protocol.oid4vc.vp.login.broker;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The configuration of an OID4VP identity provider, refusing to be saved when it is incoherent.
 *
 * <p><b>Why here.</b> Keycloak calls {@link #validate(RealmModel)} from
 * {@code RepresentationToModel.toModel}, reached by {@code IdentityProvidersResource} on create and
 * {@code IdentityProviderResource} on update — so both paths are covered, and the administration
 * console turns the exception into a message on screen. This is the same shape Keycloak uses for
 * its own brokers ({@code OAuth2IdentityProviderConfig}, {@code OIDCIdentityProviderConfig}), and
 * it is the reason {@code createConfig()} must return this class rather than a bare
 * {@link IdentityProviderModel}.</p>
 *
 * <p><b>Why refuse rather than warn.</b> These rules describe configurations that cannot work, not
 * ones that are merely unusual. Accepting them buys an administrator nothing: the cost arrives
 * later, as a holder who cannot sign in, with the diagnosis in a server log nobody is reading at
 * that moment. Refusing moves the same diagnosis to the person who can still act on it.</p>
 *
 * <p><b>Messages name the fields as the screen labels them</b>, not by their configuration keys.
 * Somebody reading the error is looking at a form, and {@code ownIssuerAnchorsPem} appears nowhere
 * on it.</p>
 */
public class Oid4vpIdentityProviderConfig extends IdentityProviderModel {

    /**
     * The fields the provider dereferences with no guard and no default, mapped to the label the
     * form shows for each.
     *
     * <p><b>This is the single source of truth for "mandatory".</b> {@link #validate(RealmModel)}
     * enforces it, {@code Oid4vpIdentityProviderFactory} marks the same properties required, and
     * anything later wanting to render that state reads it here rather than restating the list.
     * A second copy would be a second thing to update the day a field gains a default.</p>
     *
     * <p>Everything else is absent on purpose. {@code ttlSeconds}, {@code subjectClaim},
     * {@code subjectPolicy} and {@code reissueBeforeSeconds} all have defaults, and demanding a
     * value where an answer already exists teaches administrators that the asterisks are
     * arbitrary. {@code matchingClaim} is left out too: it is dereferenced without a default, but
     * that a blank one is illegitimate has not been established, and marking it wrongly would lock
     * existing realms out of their own configuration.</p>
     */
    static final Map<String, String> REQUIRED_FIELDS;

    static {
        Map<String, String> required = new LinkedHashMap<>();
        required.put(Oid4vpConfig.TRUST_ANCHORS_PEM, "Trust Anchors (PEM)");
        required.put(Oid4vpConfig.DCQL_QUERY_JSON, "DCQL Query (JSON)");
        REQUIRED_FIELDS = Collections.unmodifiableMap(required);
    }

    @Override
    public void validate(RealmModel realm) {
        // Reported one at a time, in form order: an administrator fixes the first thing named, and
        // a list of four is read as one wall of text rather than four instructions.
        for (Map.Entry<String, String> field : REQUIRED_FIELDS.entrySet()) {
            if (!isSet(field.getKey())) {
                throw new IllegalArgumentException(
                    "'" + field.getValue() + "' is required: the provider reads it with no default "
                        + "and no guard, so a login would fail on it rather than on anything the "
                        + "holder did");
            }
        }

        // Pinning our own card to our own issuer. Configured without its anchors, EVERY credential
        // of that vct is refused, and that refusal is fatal to the whole transaction rather than a
        // fallback to the PID — so a legitimate holder is locked out entirely. The same
        // inconsistency is already reported at authentication time; saying it at save time is the
        // only version an administrator hears.
        // Signing material, one way or the other. Not in REQUIRED_FIELDS because that list is one
        // field to one asterisk, and this is a choice between two shapes: a realm key named here,
        // or the legacy pair pasted below. Whether the named key EXISTS is deliberately not checked
        // — validate() runs during realm import before any component exists, and a rule that reads
        // the realm would stop a correct realm from importing. Measured, 2026-09-08: the same
        // exception answers 400 on the admin path, 500 on an API import, and stops the server
        // outright on --import-realm.
        if (!isSet(Oid4vpConfig.SIGNING_KEY_REF)
            && !(isSet(Oid4vpConfig.SIGNING_KEY_PEM) && isSet(Oid4vpConfig.SIGNING_CERT_PEM))) {
            throw new IllegalArgumentException(
                "This provider needs something to sign its requests with: name a realm key in "
                    + "'Signing Key (realm key)', or fill both 'Signing Key (PEM)' and "
                    + "'Signing Certificate (PEM)'");
        }

        if (isSet(Oid4vpConfig.OWN_VCT) && !isSet(Oid4vpConfig.OWN_ISSUER_ANCHORS_PEM)) {
            throw new IllegalArgumentException(
                "'Own Issuer Anchors (PEM)' is required when 'Own Credential Type (vct)' is set: "
                    + "without it every credential of that type is refused, and the refusal ends "
                    + "the whole authentication rather than falling back to another credential");
        }
    }

    private boolean isSet(String key) {
        String value = getConfig().get(key);
        return value != null && !value.isBlank();
    }
}
