# The RUNTIME image: Keycloak 26.7.0 carrying the OID4VP extension.
#
# Not to be confused with tools/account-console/Containerfile.node, which builds the account
# console. This one assembles; it compiles nothing. Build the three jars first — see
# docs/GETTING-STARTED.md.
#
# `docker build` and `podman build` consume this identically:
#
#   docker build -f Containerfile -t eudi-keycloak-extension:26.7.0 .
#
# The version is pinned, never `latest`. Part of this extension was built by disassembling the
# bytecode of this precise release — VerifiableCredentialOfferActionConfig, and the order in which
# required actions are evaluated. A version drift would not fail at compile time; it would fail in
# operation. Source of truth: <keycloak.version> in pom.xml. The two FROM lines below must be kept
# aligned with it by hand.
FROM quay.io/keycloak/keycloak:26.7.0 AS builder

# Explicit paths, never a wildcard: `oid4vp-core-*.jar` would also carry
# `oid4vp-core-0.1.0-SNAPSHOT-tests.jar`, which is the simulated wallet and its deliberate cheat
# modes, into a production image.
COPY oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar   /opt/keycloak/providers/
COPY oid4vp-login/target/oid4vp-login-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/
# The rebuilt account console. It carries the `oid4vp` account theme and the front-end bundle, and
# is produced by the command in docs/GETTING-STARTED.md — this image compiles the front end no more
# than it compiles the Java.
COPY account-console/oid4vp-account/target/oid4vp-account-ui-0.1.0-SNAPSHOT.jar /opt/keycloak/providers/

# The database vendor is a BUILD option, not a runtime one. Under `start --optimized`, anything not
# baked here and supplied only at startup — an environment variable, a command-line argument — is
# silently ignored. Change it and you must rebuild the image; you cannot fix it in a manifest.
#
#   docker build --build-arg KC_DB=dev-file ...
#
# `start-dev` overrides it anyway, so the demo in docs/GETTING-STARTED.md is unaffected.
ARG KC_DB=postgres

# Without these three features, issuing our own card is inert and the unified flow collapses to the
# PID alone. `--health-enabled` and `--metrics-enabled` are build options too, and baking them is
# what makes `start --optimized` safe for a deployment that expects them.
RUN /opt/keycloak/bin/kc.sh build \
      --db="${KC_DB}" --health-enabled=true --metrics-enabled=true \
      --features=oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer

# Same version as the builder above — see the pinning note.
FROM quay.io/keycloak/keycloak:26.7.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
