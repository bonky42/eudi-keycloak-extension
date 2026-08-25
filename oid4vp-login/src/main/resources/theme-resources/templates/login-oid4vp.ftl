<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header">
        ${msg("oid4vpLoginTitle","Sign in with your wallet")}
    <#elseif section = "form">
        <div id="oid4vp-login">
            <p id="oid4vp-instructions">
                ${msg("oid4vpScanInstructions","Scan the QR code with the wallet on your phone — or, if your wallet is on this device, open the link below.")}
            </p>

            <#if qrDataUri?has_content>
                <div id="oid4vp-qr">
                    <img id="oid4vp-qr-img" src="${qrDataUri}" width="240" height="240"
                         alt="${msg("oid4vpQrAlt","QR code to scan with your wallet")}"/>
                </div>
            </#if>

            <p id="oid4vp-link">
                <a id="oid4vp-wallet-link" href="${walletUri}">${msg("oid4vpOpenWallet","Open in wallet on this device")}</a>
            </p>

            <p id="oid4vp-status" role="status" aria-live="polite">
                ${msg("oid4vpWaiting","Waiting for your wallet…")}
            </p>

            <p id="oid4vp-error" style="display:none;">
                <span id="oid4vp-error-text"></span>
                <a id="oid4vp-retry" href="${url.loginUrl}">${msg("oid4vpRetry","Try again")}</a>
            </p>

            <script type="text/javascript">
                (function () {
                    var statusUrl = "${statusUrl?no_esc}";
                    var completeUrl = "${completeUrl?no_esc}";

                    var statusEl = document.getElementById("oid4vp-status");
                    var errBox = document.getElementById("oid4vp-error");
                    var errText = document.getElementById("oid4vp-error-text");
                    var stopped = false;

                    function fail(message) {
                        stopped = true;
                        if (statusEl) { statusEl.style.display = "none"; }
                        if (errText) { errText.textContent = message; }
                        if (errBox) { errBox.style.display = ""; }
                    }

                    function poll() {
                        if (stopped) { return; }
                        fetch(statusUrl, { headers: { "Accept": "application/json" }, cache: "no-store" })
                            .then(function (r) { return r.json(); })
                            .then(function (data) {
                                var s = data && data.status;
                                if (s === "completed") {
                                    stopped = true;
                                    window.location.href = completeUrl;
                                } else if (s === "failed") {
                                    fail("Presentation was rejected.");
                                } else if (s === "expired") {
                                    fail("The login request expired.");
                                } else {
                                    setTimeout(poll, 2000);
                                }
                            })
                            .catch(function () { setTimeout(poll, 2000); });
                    }

                    setTimeout(poll, 2000);
                })();
            </script>
        </div>
    </#if>
</@layout.registrationLayout>
