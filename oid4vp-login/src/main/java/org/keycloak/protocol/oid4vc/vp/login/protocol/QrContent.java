package org.keycloak.protocol.oid4vc.vp.login.protocol;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class QrContent {
    /** Builds the URI the QR code encodes:
     *  openid4vp://?client_id={clientId}&request_uri={requestUri}
     *  with both values URL-encoded. */
    public static String walletUri(String clientId, String requestUri) {
        String encodedClientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8);
        String encodedRequestUri = URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
        return "openid4vp://?" + "client_id=" + encodedClientId + "&request_uri=" + encodedRequestUri;
    }
}
