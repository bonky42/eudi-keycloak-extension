package org.keycloak.protocol.oid4vc.vp.login.admin;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

import java.time.Clock;

/**
 * Mounts this extension's administration endpoints under {@code /admin/realms/{realm}/oid4vp}.
 *
 * <p>Under the admin path rather than the realm one, which is what gets them Keycloak's own admin
 * authentication before a line of ours runs — and an {@link AdminPermissionEvaluator} to ask for
 * rights on top. The realm path would have served the same JSON to anyone who asked.
 *
 * <p><b>The id is the path segment.</b> Renaming it moves the endpoint, and nothing would say so:
 * the console would simply get a 404.
 */
public class Oid4vpAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "oid4vp";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new AdminRealmResourceProvider() {
            @Override
            public Object getResource(KeycloakSession session, RealmModel realm,
                                      AdminPermissionEvaluator auth, AdminEventBuilder events) {
                // The realm is not passed on: it is already what bounds the key lookup below, and
                // a resource holding it too could drift from the one the keys came from.
                return new SigningCertificateResource(
                    auth, () -> session.keys().getKeysStream(realm), Clock.systemUTC());
            }

            @Override
            public void close() {
            }
        };
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
