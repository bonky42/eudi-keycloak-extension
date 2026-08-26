<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("oid4vpLoginTitle")}
    <#elseif section = "form">
        <div id="oid4vp-login">

            <#-- Why we are asking. OpenID4VP 1.0 section 6.2 asks the verifier to display this and
                 defines no way to send it to the wallet, so this page is the only place it can
                 appear. advancedMsg resolves a ${key} against the bundle and returns anything else
                 verbatim — the same idiom Keycloak's consent screen uses for admin-entered text.
                 An administrator who clears the field is choosing to say nothing. -->
            <#if requestPurpose?? && requestPurpose?has_content>
                <p id="oid4vp-purpose">${advancedMsg(requestPurpose)}</p>
            </#if>

            <#-- What is being asked for, read from the DCQL actually being sent. A claim with no
                 label falls back to its technical name rather than vanishing: the page must never
                 ask for something it does not show.

                 The heading lives INSIDE the panel, not above it. It names the list, so leaving it
                 outside would frame the items and orphan their own label — a decorated list rather
                 than one block. `aria-labelledby` states that relationship for a screen reader,
                 which the visual grouping alone does not carry. -->
            <#if requestedClaims?? && requestedClaims?size gt 0>
                <div id="oid4vp-requested">
                    <p id="oid4vp-shared-intro">${msg("oid4vpSharedIntro")}</p>
                    <ul id="oid4vp-shared" aria-labelledby="oid4vp-shared-intro">
                        <#list requestedClaims as claim>
                            <li>${msg("oid4vpClaim." + claim, claim)}</li>
                        </#list>
                    </ul>
                </div>
            </#if>

            <p id="oid4vp-instructions">${msg("oid4vpScanInstructions")}</p>

            <#-- The two paths, link first. Nobody scans a code with the device showing it, so on a
                 phone the code is the useless half and above the link it buries the only usable
                 path. This order is also the right one for a screen reader: the actionable thing
                 first. The stylesheet below lifts the code above on a wide screen with a mouse. -->
            <div id="oid4vp-paths">
                <p id="oid4vp-link">
                    <a id="oid4vp-wallet-link" href="${walletUri}">${msg("oid4vpOpenWallet")}</a>
                </p>
                <p id="oid4vp-link-hint" hidden>${msg("oid4vpLinkHint")}</p>

                <#if qrDataUri?has_content>
                    <div id="oid4vp-qr">
                        <img id="oid4vp-qr-img" src="${qrDataUri}" width="240" height="240"
                             alt="${msg("oid4vpQrAlt")}"/>
                    </div>
                </#if>
            </div>

            <p id="oid4vp-status" role="status" aria-live="polite"
               data-ttl-seconds="${ttlSeconds?c}"
               data-msg-waiting="${msg("oid4vpWaiting")}"
               data-msg-expires-in="${msg("oid4vpExpiresIn", "{0}")}"
               data-msg-expired="${msg("oid4vpExpired")}"
               data-msg-rejected="${msg("oid4vpRejected")}"
               data-msg-connection-lost="${msg("oid4vpConnectionLost")}">
                ${msg("oid4vpWaiting")}
            </p>
            <p id="oid4vp-countdown" aria-hidden="true"></p>

            <p id="oid4vp-error" hidden>
                <span id="oid4vp-error-text"></span>
                <a id="oid4vp-retry" href="${url.loginUrl}">${msg("oid4vpRetry")}</a>
            </p>

            <style>
                #oid4vp-paths { display: flex; flex-direction: column; }
                /* Scanning is the likely gesture on a wide screen with a mouse, and impossible on
                   the device rendering the code. Decided by the shape of the screen, never by the
                   user agent, and without moving anything in the DOM. */
                @media (min-width: 600px) and (any-pointer: fine) {
                    #oid4vp-paths #oid4vp-qr { order: -1; }
                }
                /* The list of data leaving the wallet is the most consequential thing on this
                   page, and as plain prose it read as an aside. This gives it an edge — open on
                   the right, so it reads as a boundary being crossed rather than as a card, and
                   so it does not stack a box inside the card the theme already draws.

                   Every colour derives from currentColor: this template is rendered inside a
                   theme we do not own, in light and dark, and copying that theme's tokens would
                   drift the day it changes. The flat greys on the line above are the fallback for
                   an engine without color-mix; they are dull but legible on either ground. */
                #oid4vp-requested {
                    border-left: 3px solid rgba(128, 128, 128, 0.45);
                    border-left-color: color-mix(in srgb, currentColor 38%, transparent);
                    background: rgba(128, 128, 128, 0.06);
                    background: color-mix(in srgb, currentColor 5%, transparent);
                    border-radius: 0 4px 4px 0;
                    padding: 0.8em 1em;
                    margin: 0 0 1em;
                }
                #oid4vp-shared-intro { margin: 0 0 0.4em; font-weight: 500; }
                #oid4vp-shared { margin: 0; }
                #oid4vp-countdown { font-variant-numeric: tabular-nums; }
            </style>

            <script type="text/javascript">
                (function () {
                    var statusUrl = "${statusUrl?no_esc}";
                    var completeUrl = "${completeUrl?no_esc}";

                    var statusEl = document.getElementById("oid4vp-status");
                    var countdownEl = document.getElementById("oid4vp-countdown");
                    var errBox = document.getElementById("oid4vp-error");
                    var errText = document.getElementById("oid4vp-error-text");
                    var hintEl = document.getElementById("oid4vp-link-hint");
                    var linkEl = document.getElementById("oid4vp-wallet-link");

                    // Every string comes from the bundle through the markup. Nothing user-visible is
                    // written here, because a string in a script cannot be translated.
                    function msg(name) { return statusEl.getAttribute("data-msg-" + name) || ""; }

                    var ttl = parseInt(statusEl.getAttribute("data-ttl-seconds"), 10) || 120;
                    var deadline = Date.now() + ttl * 1000;
                    var delay = 1000;        // the wallet usually answers fast; ask often at first
                    var MAX_DELAY = 5000;
                    var GRACE_MS = 5000;     // the server is authoritative; outlive our own clock
                    var failures = 0;
                    var MAX_FAILURES = 5;
                    var stopped = false;
                    var timer = null;
                    var announced = {};

                    function fail(text) {
                        stopped = true;
                        if (timer) { clearTimeout(timer); }
                        statusEl.hidden = true;
                        countdownEl.hidden = true;
                        errText.textContent = text;
                        errBox.hidden = false;
                    }

                    // Display only. The server decides expiry, so a clock running fast here can
                    // shorten what is shown but can never end a session early.
                    function tick() {
                        if (stopped) { return; }
                        var left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
                        var template = statusEl.getAttribute("data-msg-expires-in") || "{0}";
                        var shown = template.replace("{0}", left + "s");
                        countdownEl.textContent = shown;
                        // Announced at thresholds only: a live region that ticks every second is
                        // unusable with a screen reader.
                        if ((left === 60 || left === 30 || left === 10) && !announced[left]) {
                            announced[left] = true;
                            statusEl.textContent = shown;
                        }
                    }

                    function schedule() {
                        if (stopped) { return; }
                        if (Date.now() > deadline + GRACE_MS) { fail(msg("expired")); return; }
                        timer = setTimeout(poll, document.hidden ? MAX_DELAY : delay);
                        delay = Math.min(Math.round(delay * 1.5), MAX_DELAY);
                    }

                    function poll() {
                        if (stopped) { return; }
                        fetch(statusUrl, { headers: { "Accept": "application/json" }, cache: "no-store" })
                            .then(function (r) { return r.json(); })
                            .then(function (data) {
                                failures = 0;
                                var s = data && data.status;
                                if (s === "completed") { stopped = true; window.location.href = completeUrl; }
                                else if (s === "failed") { fail(msg("rejected")); }
                                else if (s === "expired") { fail(msg("expired")); }
                                else { schedule(); }
                            })
                            .catch(function () {
                                // Never loop forever on a server that has stopped answering.
                                failures += 1;
                                if (failures >= MAX_FAILURES) { fail(msg("connection-lost")); }
                                else { schedule(); }
                            });
                    }

                    // The same-device path backgrounds this page while the holder is in their
                    // wallet. Slow down while hidden, and ask again the instant it comes back.
                    document.addEventListener("visibilitychange", function () {
                        if (!document.hidden && !stopped) {
                            if (timer) { clearTimeout(timer); }
                            delay = 1000;
                            poll();
                        }
                    });

                    // A custom scheme with no handler does nothing at all, and says nothing. Still
                    // holding focus a moment after the click is what that looks like.
                    if (linkEl && hintEl) {
                        linkEl.addEventListener("click", function () {
                            setTimeout(function () {
                                if (!document.hidden) { hintEl.hidden = false; }
                            }, 800);
                        });
                    }

                    setInterval(tick, 1000);
                    tick();
                    schedule();
                })();
            </script>

            <#-- The language switcher, repointed.

                 Keycloak renders it from locale.supported[].url, which is THIS page's URL with
                 kc_locale added. That URL cannot be requested twice: /broker/{alias}/login wants a
                 single-use session_code the switcher never carries, so following it answers 400.
                 The query string, though, is already right — Keycloak puts client_id, tab_id and
                 client_data on it, which is exactly what restarting the flow needs. So only the
                 path is wrong, and only the path is replaced.

                 Rewriting the URLs rather than intercepting the event is deliberate. The
                 keycloak.v2 theme carries onchange="window.location.href=this.value" as an inline
                 attribute, which a listener cannot cancel with stopPropagation; leaving that
                 handler alone and changing where it points needs no interception at all, and the
                 same loop covers the base theme, which renders anchors and no <select>.

                 Nothing here assumes the switcher exists. With internationalisation off, or on a
                 future theme that renames these elements, every query below matches nothing and
                 the page is unchanged. -->
            <script type="text/javascript">
                (function () {
                    var endpoint = "${localeEndpoint?no_esc}";
                    if (!endpoint) { return; }

                    function repoint(raw) {
                        try {
                            var here = window.location.href;
                            var target = new URL(endpoint, here);
                            // Carries kc_locale AND the client_id/tab_id/client_data that the
                            // restart needs. Copied wholesale so a future Keycloak adding another
                            // parameter keeps working without a change here.
                            target.search = new URL(raw, here).search;
                            return target.toString();
                        } catch (e) {
                            return null;   // an unparsable URL leaves the option as it was
                        }
                    }

                    function apply() {
                        var opts = document.querySelectorAll("#login-select-toggle option[value]");
                        for (var i = 0; i < opts.length; i++) {
                            var v = repoint(opts[i].value);
                            if (v) { opts[i].value = v; }
                        }
                        var links = document.querySelectorAll("#kc-locale a[href], #language-switch1 a[href]");
                        for (var j = 0; j < links.length; j++) {
                            var h = repoint(links[j].getAttribute("href"));
                            if (h) { links[j].setAttribute("href", h); }
                        }
                    }

                    // The switcher is rendered by template.ftl, outside this section: run once the
                    // document is parsed rather than trusting it to appear above us.
                    if (document.readyState === "loading") {
                        document.addEventListener("DOMContentLoaded", apply);
                    } else {
                        apply();
                    }
                })();
            </script>
        </div>
    </#if>
</@layout.registrationLayout>
