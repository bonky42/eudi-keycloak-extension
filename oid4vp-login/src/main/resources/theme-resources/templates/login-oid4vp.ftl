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
                 ask for something it does not show. -->
            <#if requestedClaims?? && requestedClaims?size gt 0>
                <p id="oid4vp-shared-intro">${msg("oid4vpSharedIntro")}</p>
                <ul id="oid4vp-shared">
                    <#list requestedClaims as claim>
                        <li>${msg("oid4vpClaim." + claim, claim)}</li>
                    </#list>
                </ul>
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
                #oid4vp-shared { margin: 0 0 1em; }
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
        </div>
    </#if>
</@layout.registrationLayout>
