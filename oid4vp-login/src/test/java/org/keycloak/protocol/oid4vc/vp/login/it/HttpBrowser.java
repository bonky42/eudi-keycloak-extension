package org.keycloak.protocol.oid4vc.vp.login.it;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A browser-shaped HTTP client for integration tests: it follows redirects itself and carries
 * cookies across them.
 *
 * <p>Java's {@code CookieManager} mishandles Keycloak's cookies (their Path and SameSite
 * attributes), so cookies are tracked by name here and every one of them is replayed on every
 * request. That is correct for a single-host flow, which is all these tests perform.</p>
 */
final class HttpBrowser {

    private static final int MAX_HOPS = 10;

    private final HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    private final Map<String, String> cookies = new LinkedHashMap<>();

    /** Follows redirects from {@code url} and returns the first non-redirect response. */
    HttpResponse<String> get(String url) throws Exception {
        String current = url;
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(current)).GET();
            if (!cookies.isEmpty()) {
                request.header("Cookie", join());
            }
            HttpResponse<String> response = client.send(request.build(),
                HttpResponse.BodyHandlers.ofString());
            harvest(response);

            int status = response.statusCode();
            if (status < 300 || status > 399) {
                return response;
            }
            String location = response.headers().firstValue("Location")
                .orElseThrow(() -> new IllegalStateException(status + " without a Location header"));
            current = URI.create(current).resolve(location).toString();
        }
        throw new IllegalStateException("too many redirects starting from " + url);
    }

    private void harvest(HttpResponse<String> response) {
        for (String header : response.headers().allValues("Set-Cookie")) {
            String pair = header.split(";", 2)[0];
            int equals = pair.indexOf('=');
            if (equals > 0) {
                cookies.put(pair.substring(0, equals).trim(), pair.substring(equals + 1).trim());
            }
        }
    }

    private String join() {
        StringBuilder joined = new StringBuilder();
        cookies.forEach((name, value) -> {
            if (joined.length() > 0) {
                joined.append("; ");
            }
            joined.append(name).append('=').append(value);
        });
        return joined.toString();
    }
}
