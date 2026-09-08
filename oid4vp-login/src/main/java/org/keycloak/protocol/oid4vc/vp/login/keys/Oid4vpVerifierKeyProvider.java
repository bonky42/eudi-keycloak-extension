package org.keycloak.protocol.oid4vc.vp.login.keys;

import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.protocol.oid4vc.vp.request.VerifierClientId;

import java.util.stream.Stream;

public class Oid4vpVerifierKeyProvider implements KeyProvider {

    private final KeyWrapper key;

    public Oid4vpVerifierKeyProvider(ComponentModel model) {
        this.key = new KeyWrapper();
        key.setPrivateKey(VerifierPem.privateKey(model.get(Oid4vpVerifierKeyProviderFactory.PRIVATE_KEY_PEM)));
        key.setCertificate(VerifierPem.certificate(model.get(Oid4vpVerifierKeyProviderFactory.CERTIFICATE_PEM)));
        key.setPublicKey(key.getCertificate().getPublicKey());
        key.setKid(VerifierClientId.fingerprint(key.getCertificate()));
        // Without these the key is orphaned: the realm key manager groups by provider id, and it
        // simply never appears — no error, no log line. Found against a running server while every
        // unit test was green.
        key.setProviderId(model.getId());
        key.setProviderPriority(model.get(Attributes.PRIORITY_KEY, 0L));
        key.setType(KeyType.EC);
        key.setAlgorithm(Algorithm.ES256);
        key.setUse(KeyUse.SIG);
        // KeyStatus.from takes (active, enabled) — the reverse of the order the console shows the
        // two switches in, and the reverse of how Attributes names them. Swapped, an enabled key
        // reads back DISABLED, which is silent: the key simply never appears anywhere.
        key.setStatus(KeyStatus.from(
            model.get(Attributes.ACTIVE_KEY, false),
            model.get(Attributes.ENABLED_KEY, true)));
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        return Stream.of(key);
    }
}
