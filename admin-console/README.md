# OID4VP admin console

The Keycloak administration console, rebuilt from `@keycloak/keycloak-admin-ui`, with one page of
our own: the **OID4VP Wallet** identity-provider settings.

## Why a rebuilt console and not a theme

The shipped console picks a settings component from a list of provider ids compiled into its bundle
(`providerId.includes("oidc") / ("saml") / ("spiffe") …`). A third party cannot enter that list, and
everything outside it falls to a generic renderer that:

- **demands Client ID and Client Secret** — never read by this provider, whose verifier `client_id`
  is derived from the signing certificate;
- **drops the `required` flag** the server sends, so nothing on screen says which of the fourteen
  fields must be filled.

Owning a route sidesteps that decision: React Router ranks a literal segment above a parameter, so
`identity-providers/oid4vp/add` wins over `identity-providers/:providerId/add` with no ordering
trick.

Note the contrast with the realm **Keys** screens, which are entirely descriptor-driven
(`KeyProvidersPicker` lists whatever `componentTypes` contains, `KeyProviderForm` renders it with
`DynamicComponents`). A custom key provider would need no console work at all. Same product, two
screens, two philosophies.

## Building

Everything runs in the pinned image; nothing touches a host toolchain. Run from the repository root:

```bash
CONSOLE_SRC="$PWD/eudi-keycloak-extension/admin-console" ./tools/account-console/node-build sh -c '
  cd oid4vp-admin &&
  pnpm install --frozen-lockfile &&
  pnpm run build &&
  pnpm run notices &&
  mvn -B clean package -Dskip.installnodenpm=true -Dskip.npm=true'
```

The result is `oid4vp-admin/target/oid4vp-admin-ui-0.1.0-SNAPSHOT.jar`, mounted into
`/opt/keycloak/providers/`. Serve it with **three** cache flags, not two:

```
--spi-theme--static-max-age=-1 --spi-theme--cache-themes=false --spi-theme--cache-templates=false
```

FreeMarker templates are cached separately: without the third flag a replaced `index.ftl` keeps
serving the old one. `data/tmp/kc-gzip-cache` is worth clearing too.

## The composition — half upstream, half scaffold

Neither alone works.

- **Routing: upstream's.** `createHashRouter`, root route on `"/"`. The package's routes are
  **absolute** (`/:realm/authentication`); a history router mounted on `consoleBaseUrl` rejects them
  — *"an absolute child route path must start with the combined path of all its parent routes"*.
- **Contexts: the scaffold's.** Call `initAdminClient(keycloak, environment)` by hand, then
  `AdminClientContext.Provider` → `ErrorBoundaryProvider` → `RealmContextProvider` →
  `ServerInfoProvider` → `WhoAmIContextProvider` → `RecentRealmsProvider` → `AccessContextProvider`
  → `SubGroups` → `Page`. **Do not reuse `AdminUi`** (the package's own `App`): it is written for
  their build and yields *"No provider found for the 'AdminClientContext' context"*.
- `KeycloakProvider` **outside** the router, in `main.tsx`, and `i18n.init()` **before** rendering.
- `Header` and `PageNav` come from the package, so the menu stays the real one and follows upstream.

## The wall of the published package

`@keycloak/keycloak-admin-ui` ships as a bundle whose **only** externals are `react`, `react-dom`,
`react-i18next` and `react-router-dom`. It **inlines** `@keycloak/keycloak-ui-shared`,
`react-hook-form` and PatternFly. There are therefore two copies of the shared library in the page,
and their React contexts do not see each other. Consequences, all of them measured:

1. **`DynamicComponents` is exported but unusable.** It reads the form context of *its* copy; no
   `FormProvider` written here can feed it. A page that owns its form must build its fields from the
   copy it can import — hence `src/ConfigFields.tsx`. Everything context-free (`ViewHeader`,
   `FormAccess`, `ScrollForm`, `FixedButtonsGroup`, `useConfirmDialog`) still comes from the package.
2. **Three providers must be remounted** from our copy, in `App.tsx` and not in the page:
   `ErrorBoundaryProvider` (`useFetch` calls `useErrorBoundary` unconditionally), `Help` (the `?`
   badge calls `useHelp`), and `AlertProvider`. Mounted inside the page they are torn down on every
   navigation, taking the success toast with them. Upstream has no explicit `AlertProvider`: its
   `KeycloakProvider` mounts `AlertProvider` and `Help` — which is why upstream pages work and ours
   did not.
3. **`react-hook-form` must be pinned to `7.70.0`**, the exact version `keycloak-ui-shared` pins. Any
   other resolution puts a second copy in the bundle. Check by counting `react-hook-form@` sources in
   `dist/assets/*.js.map`.
4. **`@keycloak/keycloak-admin-ui/styles.css` must be imported explicitly** — the bundle does not
   pull it in.
5. **`@patternfly/patternfly/patternfly-addons.css` too.** None of the `pf-v5-u-*` utility classes
   are defined in `base.css` or in the admin stylesheet; without this import every one of them —
   ours *and* those inside upstream components — is inert, and the page merely renders wrongly
   spaced, silently.
6. **`mainContainerId={mainPageContentId}` on the `<Page>`.** `ScrollForm` tracks the section on
   screen by reading the scrolling element **by id** and gives up in silence when it is missing: the
   jump links render, scroll on click, and never highlight.

## Four upstream bugs this page works around

- **`TextComponent` passes `required` to `FormGroup`** where PatternFly expects `isRequired`, so a
  required text area shows **no asterisk**. All four required fields of this provider are text areas.
- **`TextAreaControl` computes the asterisk with `!!props.rules?.required`** while `TextControl` goes
  through `getRuleValue()`. The long form `{ value: false, message }` is an object, hence truthy —
  state the **short** form, and only when the field really is required.
- **PatternFly's `TextArea` renders `value` conditionally**:
  `...(typeof this.props.defaultValue !== 'string' && { value })`. The empty string *is* a string, so
  passing `defaultValue=""` drops `value` and the field stays blank whatever the form holds. Pass
  `defaultValue` only when the server declares one.
- **`DynamicComponents` drops an unrecognised type** with a `console.warn`. `ConfigField` shows it
  read-only instead: silently losing a field the server declares is the defect this page exists to
  avoid.

Two integration traps of our own, for good measure: never run a server label or help text through
`t()` unguarded — i18next reads `":"` as a namespace separator, so a help text containing
`urn:eudi:pid:1=sub` comes back truncated at the first colon; use the package's own idiom,
`i18n.exists(x) ? t(x) : x`. And `NetworkError.message` already carries the server's own sentence,
so `addError(key, error)` surfaces the identity-provider validation message verbatim.

## Where things live

| Path | Role |
|---|---|
| `oid4vp-admin/src/Oid4vpSettings.tsx` | Our page: header, sections, save, delete |
| `oid4vp-admin/src/ConfigFields.tsx` | One server-declared property → the console's control for its type |
| `oid4vp-admin/src/routes.tsx` | Every stock route, plus our two |
| `oid4vp-admin/src/App.tsx` | The shell: contexts, breadcrumbs, the remounted providers |
| `oid4vp-admin/maven-resources/theme/oid4vp/admin/` | Theme: `index.ftl`, properties, messages |

The page holds no business logic. Labels, help texts, types and `required` all come from the server;
the section list decides **order**, never which fields exist — anything the server declares and the
list does not name still renders, under "Other settings".
