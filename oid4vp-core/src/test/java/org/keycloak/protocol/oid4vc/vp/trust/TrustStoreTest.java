package org.keycloak.protocol.oid4vc.vp.trust;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.vp.testsupport.TestTrustChain;

import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrustStoreTest {

    @Test
    void acceptsChainToKnownAnchor() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TrustStore store = new TrustStore(List.of(chain.caCert));
        assertEquals(chain.caCert.getSubjectX500Principal(),
            store.validateChain(List.of(chain.issuerCert, chain.caCert)).getSubjectX500Principal());
    }

    @Test
    void acceptsLeafOnlyChainWhenIssuedByAnchor() throws Exception {
        TestTrustChain chain = new TestTrustChain();
        TrustStore store = new TrustStore(List.of(chain.caCert));
        assertNotNull(store.validateChain(List.of(chain.issuerCert)));
    }

    @Test
    void rejectsChainToUnknownAnchor() {
        TestTrustChain chain = new TestTrustChain();
        TrustStore store = new TrustStore(List.of(chain.rogueCaCert));
        assertThrows(GeneralSecurityException.class,
            () -> store.validateChain(List.of(chain.issuerCert, chain.caCert)));
    }

    @Test
    void rejectsEmptyChain() {
        TrustStore store = new TrustStore(List.of(new TestTrustChain().caCert));
        assertThrows(GeneralSecurityException.class, () -> store.validateChain(List.of()));
    }
}
