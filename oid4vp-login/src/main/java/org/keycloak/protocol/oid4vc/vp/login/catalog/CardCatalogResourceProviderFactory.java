package org.keycloak.protocol.oid4vc.vp.login.catalog;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Publishes the card request page under {@code /realms/{realm}/cards}.
 *
 * <p>Served by Keycloak itself, so no extra deployment and no extra domain: the extension that
 * carries the verifier and the identity provider carries this counter too.</p>
 */
public class CardCatalogResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "cards";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override
            public Object getResource() {
                return new CardCatalogResource(session);
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
