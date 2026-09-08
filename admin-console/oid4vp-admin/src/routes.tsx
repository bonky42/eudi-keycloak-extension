import { routes as stockRoutes } from "@keycloak/keycloak-admin-ui";
import type { RouteObject } from "react-router-dom";
import App from "./App";
import { Oid4vpSettings } from "./Oid4vpSettings";

/**
 * Every stock page, plus ours.
 *
 * <p>This is why the console is rebuilt rather than grafted onto. The shipped bundle picks a
 * settings component from a list of provider ids compiled into it (`providerId.includes("oidc") /
 * ("saml") / ("spiffe") …`); a third party cannot enter that list, and everything outside it falls
 * to a generic renderer which demands Client ID and Client Secret — never read by this provider,
 * whose verifier identifier is derived from the signing certificate — while dropping the
 * `required` flag the server sends it.</p>
 *
 * <p>Owning a route sidesteps that decision: React Router ranks a literal segment above a
 * parameter, so `identity-providers/oid4vp/add` wins over `identity-providers/:providerId/add`
 * with no ordering trick.</p>
 */

// The package exports its pages as a FLAT array — `routes.d.ts` declares
// `export declare const routes: AppRouteObject[]`, with no root wrapping them. The account console
// was bitten by assuming otherwise: reading `routes[0].children` yielded nothing, the console ended
// up with our page as its only working route, and every other tab rendered blank while still being
// advertised in the menu. Both shapes are accepted so an upstream change to either degrades into
// the other rather than into an empty console.
const exported = stockRoutes as unknown as RouteObject[];
const stockPages: RouteObject[] =
  exported.length === 1 && exported[0].children ? exported[0].children! : exported;

/**
 * Absolute, like the stock ones (`/:realm/identity-providers/spiffe/add` in the shipped bundle).
 * As children of a root mounted at "/", an absolute path is valid precisely because it extends the
 * parent's; writing them relative would place them somewhere else.
 */
const ourPages: RouteObject[] = [
  { path: "/:realm/identity-providers/oid4vp/add", element: <Oid4vpSettings mode="add" /> },
  {
    path: "/:realm/identity-providers/oid4vp/:alias/settings",
    element: <Oid4vpSettings mode="edit" />,
  },
];

export const RootRoute: RouteObject = {
  // "/" and not consoleBaseUrl: the router is a HASH router, so the location it sees is the part
  // after the "#", which starts at the realm. Mounting on the console's base path made every stock
  // route an invalid absolute child.
  path: "/",
  element: <App />,
  children: [...ourPages, ...stockPages],
};

export const routes: RouteObject[] = [RootRoute];
