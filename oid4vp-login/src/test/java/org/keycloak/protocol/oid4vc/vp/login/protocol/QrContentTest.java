package org.keycloak.protocol.oid4vc.vp.login.protocol;

import org.junit.jupiter.api.Test;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class QrContentTest {
    @Test
    void buildsWalletUriWithEncodedParams() {
        String uri = QrContent.walletUri(
            "x509_san_dns:kc.example.org",
            "https://kc.example.org/realms/r/oid4vp/request/TX1");
        assertTrue(uri.startsWith("openid4vp://?"));
        assertTrue(uri.contains("client_id="));
        assertTrue(uri.contains("request_uri="));
        // request_uri must be URL-encoded: no bare :// in the query
        String q = uri.substring(uri.indexOf('?') + 1);
        String requestUri = null, clientId = null;
        for (String p : q.split("&")) {
            String[] kv = p.split("=", 2);
            if (kv[0].equals("request_uri")) requestUri = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            if (kv[0].equals("client_id")) clientId = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        assertEquals("https://kc.example.org/realms/r/oid4vp/request/TX1", requestUri);
        assertEquals("x509_san_dns:kc.example.org", clientId);
    }
}
