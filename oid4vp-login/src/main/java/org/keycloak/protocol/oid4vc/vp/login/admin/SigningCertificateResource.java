package org.keycloak.protocol.oid4vc.vp.login.admin;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.oid4vc.vp.login.keys.VerifierSigningMaterial;
import org.keycloak.protocol.oid4vc.vp.request.CertificateSummary;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import java.time.Clock;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Tells an administrator what the certificate they pasted actually says.
 *
 * <p><b>Why the server and not the console.</b> The field that matters is the {@code client_id}: it
 * is the SHA-256 of the certificate's DER, it is what the wallet compares the {@code x5c} against,
 * and it is the one thing on that form nobody can check by eye. Computed in the browser it would be
 * a second implementation of a value the server already derives — and the day the two disagree, the
 * screen is the one that lies. Here it comes from the same call the request object makes.
 *
 * <p>The rest — subject, issuer, validity, curve — is in the PEM for anyone willing to run
 * {@code openssl x509 -text}. Not having to is the point.
 *
 * <p><b>Read-only, deliberately.</b> It reads a key and computes; it writes nothing, so it raises no
 * admin event and needs no event builder. Reached under {@code /admin/realms/{realm}/oid4vp/...},
 * so Keycloak's own admin authentication applies before anything here runs, and
 * {@link AdminPermissionEvaluator} is asked for realm view rights on top. Measured against 26.7.2:
 * no token and a bad token answer 401; a user with no admin role answers 403, and so does one
 * holding {@code view-users} but not {@code view-realm}; an administrator of another realm answers
 * 403. The lookup is bounded by the realm in the path, so a key of one realm cannot be read through
 * another.
 *
 * <p><b>The HTTP mapping lives in the resource method and nowhere else.</b> {@link #summarise} is a
 * plain function over a configuration map — building a JAX-RS exception needs a {@code
 * RuntimeDelegate} that only a running server provides, so mixing the two would put the rules
 * beyond reach of any test that does not start a container.
 */
public class SigningCertificateResource {

    private final AdminPermissionEvaluator auth;
    private final Supplier<Stream<KeyWrapper>> realmKeys;
    private final Clock clock;

    SigningCertificateResource(AdminPermissionEvaluator auth,
                               Supplier<Stream<KeyWrapper>> realmKeys, Clock clock) {
        this.auth = auth;
        this.realmKeys = realmKeys;
        this.clock = clock;
    }

    /**
     * What a realm key's certificate says, asked for by the key itself.
     *
     * <p>This is what a settings form needs. Addressed by provider, a summary can only describe what
     * the last save happened to hold — it cannot answer while a provider is being created, and on an
     * existing one it describes the stored choice rather than the one on screen. Addressed by key,
     * it answers the question the form is actually asking: what would this key announce.</p>
     */
    @GET
    @Path("keys/{id}/certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateSummary keyCertificate(@PathParam("id") String id) {
        auth.realm().requireViewRealm();
        try {
            return summariseKey(id, realmKeys, clock);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage(), e);
        }
    }

    static CertificateSummary summariseKey(String id, Supplier<Stream<KeyWrapper>> realmKeys) {
        return summariseKey(id, realmKeys, Clock.systemUTC());
    }

    static CertificateSummary summariseKey(String id, Supplier<Stream<KeyWrapper>> realmKeys,
                                           Clock clock) {
        return CertificateSummary.of(
            VerifierSigningMaterial.ofKey(id, realmKeys).certificate(), clock.instant());
    }
}
