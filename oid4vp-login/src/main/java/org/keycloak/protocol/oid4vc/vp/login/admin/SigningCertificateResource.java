package org.keycloak.protocol.oid4vc.vp.login.admin;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.vp.login.protocol.Oid4vpConfig;
import org.keycloak.protocol.oid4vc.vp.request.CertificateSummary;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Map;
import java.util.Optional;

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
 * <p><b>Read-only, deliberately.</b> It reads configuration and computes; it writes nothing, so it
 * raises no admin event and needs no event builder. Reached under
 * {@code /admin/realms/{realm}/oid4vp/...}, so Keycloak's own admin authentication applies before
 * anything here runs, and {@link AdminPermissionEvaluator} is asked for realm view rights on top.
 *
 * <p><b>The HTTP mapping lives in the resource method and nowhere else.</b> {@link #summarise} is a
 * plain function over a configuration map — building a JAX-RS exception needs a {@code
 * RuntimeDelegate} that only a running server provides, so mixing the two would put the rules
 * beyond reach of any test that does not start a container.
 */
public class SigningCertificateResource {

    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final Clock clock;

    SigningCertificateResource(RealmModel realm, AdminPermissionEvaluator auth, Clock clock) {
        this.realm = realm;
        this.auth = auth;
        this.clock = clock;
    }

    /**
     * @param alias the identity provider's alias, as it appears in the realm
     * @return what its configured signing certificate says about itself
     */
    @GET
    @Path("providers/{alias}/signing-certificate")
    @Produces(MediaType.APPLICATION_JSON)
    public CertificateSummary signingCertificate(@PathParam("alias") String alias) {
        auth.realm().requireViewRealm();

        IdentityProviderModel provider = realm.getIdentityProvidersStream()
            .filter(candidate -> candidate.getAlias().equals(alias))
            .findFirst()
            .orElseThrow(() -> new NotFoundException("No identity provider with alias " + alias));

        try {
            return summarise(provider.getConfig(), clock)
                .orElseThrow(() -> new NotFoundException(
                    "This provider has no signing certificate configured"));
        } catch (IllegalArgumentException e) {
            // Unreadable is a mistake already made, not a field left empty: saying so here is what
            // keeps it from surfacing later as a wallet refusing the request for reasons that name
            // none of it.
            throw new BadRequestException(e.getMessage(), e);
        }
    }

    static Optional<CertificateSummary> summarise(Map<String, String> config) {
        return summarise(config, Clock.systemUTC());
    }

    /**
     * @return empty when no certificate is configured — a form being filled in, not a fault
     * @throws IllegalArgumentException when one is configured but cannot be read
     */
    static Optional<CertificateSummary> summarise(Map<String, String> config, Clock clock) {
        String pem = config == null ? null : config.get(Oid4vpConfig.SIGNING_CERT_PEM);
        if (pem == null || pem.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(CertificateSummary.of(parse(pem), clock.instant()));
    }

    private static X509Certificate parse(String pem) {
        X509Certificate certificate;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalArgumentException("The signing certificate is not readable as PEM", e);
        }
        if (certificate == null) {
            // generateCertificate answers null rather than throwing when the input holds no PEM
            // block at all, which is exactly what a half-pasted field looks like.
            throw new IllegalArgumentException("The signing certificate is not readable as PEM");
        }
        return certificate;
    }
}
