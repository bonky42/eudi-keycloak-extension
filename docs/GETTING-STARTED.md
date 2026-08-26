# Getting started

From a fresh clone to a Keycloak that accepts an EU Digital Identity Wallet.

Everything runs in containers. You need a container engine and `openssl`; you do not need a JDK,
Maven or Node. Commands use `docker`; `podman` accepts all of them unchanged.

Two options appear on every mount and are not style:

- **`"$PWD"`, never `./`.** A bind-mount source without a leading `/` can be read as a *named
  volume* and created empty. Keycloak then starts with an empty `providers/` directory and no
  extension at all, without an error.
- **`:z`** relabels for SELinux. It comes from Docker, both engines understand it, and it is
  harmless where SELinux is absent.

## 1. Build the extension

```bash
docker run --rm -v "$PWD":/workspace:z -v kc-oid4vp-m2:/root/.m2:z -w /workspace \
  maven:3.9-eclipse-temurin-17 mvn package
```

The named volume keeps the Maven repository between runs; without it every build re-downloads the
dependency tree. This produces:

```
oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar
oid4vp-login/target/oid4vp-login-0.1.0-SNAPSHOT.jar
```

`mvn test` alone runs the unit suite without packaging.

## 2. Generate the demo realm

```bash
./scripts/prepare-demo --host localhost
```

This writes `demo/out/`: a demo issuer CA, a verifier key and certificate, and `realm.json` — the
realm template with those three PEMs substituted in.

**`--host` is load-bearing.** The verifier certificate's SAN DNS entry must equal the hostname the
wallet will use, because the `client_id` is derived from it. Getting it wrong produces a request a
conformant wallet refuses, usually without saying why. Re-run with `--force` to regenerate.

The two key pairs are deliberately independent: the verifier signs the Request Object, the demo
issuer CA becomes the trust anchor for the cards a wallet presents. Collapsing them into one would
work, and would teach that a verifier is its own trust anchor — the opposite of what this does.

## 3. Run it

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/oid4vp-core/target/oid4vp-core-0.1.0-SNAPSHOT.jar":/opt/keycloak/providers/oid4vp-core.jar:z \
  -v "$PWD/oid4vp-login/target/oid4vp-login-0.1.0-SNAPSHOT.jar":/opt/keycloak/providers/oid4vp-login.jar:z \
  -v "$PWD/demo/out/realm.json":/opt/keycloak/data/import/realm-oid4vp-demo.json:z \
  quay.io/keycloak/keycloak:26.7.0 start-dev --import-realm
```

- Admin console: <http://localhost:8080/admin/> — `admin` / `admin`
- Demo realm account page: <http://localhost:8080/realms/oid4vp-demo/account>

**Published on loopback on purpose.** This server accepts `admin`/`admin` and keeps everything in
memory. Replace `127.0.0.1:8080:8080` with `8080:8080` and anyone who can reach the host gets its
admin console — and if you do, re-run `prepare-demo --host <that-name> --force` first, or the
certificate will not match.

The demo realm declares one identity provider, `oid4vp`, already configured. Its DCQL asks for a
**PID only**, which is the half of this project that needs no patched wallet.

## 4. Sign in with a real wallet

This is where the preconditions bite, and they are not this project's doing:

- A wallet will not talk to cleartext HTTP, so the instance needs **public HTTPS**.
- The `client_id` the wallet checks is derived from the hostname, so the **verifier certificate's
  SAN must match** the public name — hence `prepare-demo --host`.
- The wallet must hold a PID from an issuer in the anchors the realm trusts. The demo CA generated
  above signs nothing a real wallet holds; to accept official test PIDs, replace `trustAnchorsPem`
  on the identity provider with the EUDI pre-production anchors.

Without a phone and a public name, the demo above still exercises everything up to the point where
a wallet would answer: the realm imports, the identity provider builds a signed Request Object, and
the login page renders its QR code.

## 5. Build the account console (optional)

Only needed for the card-issuance page; the login flow does not use it.

```bash
docker build -f tools/account-console/Containerfile.node \
  -t keycloak-account-ui-build:1 tools/account-console/

docker run --rm -v "$PWD":/src:z -w /src keycloak-account-ui-build:1 sh -c '
  cd account-console/oid4vp-account &&
  pnpm install --frozen-lockfile &&
  pnpm run notices &&
  pnpm run build &&
  mvn -B clean package -Dskip.installnodenpm=true -Dskip.npm=true'
```

`clean` is not optional: without it Maven keeps the previous bundle and the JAR ships two hashed
`main-*.js` files. Both are valid, so nothing fails — the artefact just doubles in size and stops
saying which build it is.

`pnpm run notices` is not optional either. The bundle inlines its dependencies — PatternFly, React,
and the Red Hat fonts Keycloak's own account UI carries — so the JAR distributes them while this
repository does not. It writes `META-INF/THIRD-PARTY-NOTICES.txt` into the artefact, generated from
the resolved dependency tree so it cannot drift from `pnpm-lock.yaml`.

Mount the result the same way as the other two:

```
-v "$PWD/account-console/oid4vp-account/target/oid4vp-account-ui-0.1.0-SNAPSHOT.jar":/opt/keycloak/providers/oid4vp-account-ui.jar:z
```

Issuance also needs upstream [`eudi-lib-android-wallet-core#369`](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/pull/369),
which is not merged. Until it is, a stock wallet cannot complete the card request.

## 6. Build a runtime image (optional)

Steps 1 to 3 need no image: they mount the jars into the upstream Keycloak. An image is for
deploying somewhere, and it assembles rather than compiles — build all three jars first, including
the console from step 5.

```bash
docker build -f Containerfile -t eudi-keycloak-extension:26.7.0 .

docker run --rm -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/demo/out/realm.json":/opt/keycloak/data/import/realm-oid4vp-demo.json:z \
  eudi-keycloak-extension:26.7.0 start-dev --import-realm
```

**The database vendor is a build option, not a runtime one.** Under `start --optimized`, anything
not baked into the image and supplied only at startup — an environment variable, a command-line
argument — is silently ignored. The image defaults to `postgres`; change it and you must rebuild:

```bash
docker build --build-arg KC_DB=dev-file -f Containerfile -t eudi-keycloak-extension:26.7.0 .
```

`start-dev`, as used above, overrides it anyway, so the demo is unaffected either way.

Server features are a build option for the same reason. A deployment needing more than the three
this extension requires adds them at build time, since supplying them at startup is silently
ignored under `start --optimized`:

```bash
docker build --build-arg KC_FEATURES=oid4vc-vci,oid4vc-vci-preauth-code,oid4vc-vci-rest-credential-offer,scim-api \
  -f Containerfile -t eudi-keycloak-extension:26.7.0 .
```

## When something fails

Several failure messages in this ecosystem do not describe their cause — a wallet saying a document
is "not available" most often means the request asked for no claims at all. Start with
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md); every entry there was reproduced against a real wallet
on a real device.
