import type { RouteObject } from "react-router-dom";
import { routes as stockRoutes } from "@keycloak/keycloak-account-ui";
import App from "./App";
import { environment } from "./environment";
import { RequestCard } from "./RequestCard";

/**
 * The stock console pages, taken from the package itself rather than re-declared.
 *
 * The scaffold hand-lists a SUBSET — it omits Verifiable Credentials and Organizations — and its
 * paths differ from the stock ones (`deviceActivity` instead of `device-activity`). Re-declaring
 * that list means owning it forever and silently losing every page the upstream adds. Taking the
 * package's own children costs nothing and keeps us aligned across upgrades.
 *
 * Observed on 2026-08-17, from the rebuilt console in production: the Verifiable Credentials tab had
 * vanished and Groups and Resources had appeared, because the scaffold list is both incomplete and
 * ungated.
 */
const exported = stockRoutes as RouteObject[];

const stockPages = (
  // The package exports the pages as a FLAT list — its `routes.d.ts` declares no root route, and
  // reading `routes[0].children` yields nothing. Getting that wrong left the console with our page
  // as its ONLY working route while the menu still advertised every other tab: they all rendered
  // blank. Reported by the user on 2026-08-17.
  //
  // Both shapes are accepted so an upstream change to either one degrades into the other rather
  // than into an empty console.
  exported.length === 1 && exported[0].children ? exported[0].children : exported
).filter(
  // The generic content route belongs to the theme-based extension mechanism, which a rebuilt
  // console does not use. Keeping it would add a route we never populate.
  (route) => route.path !== "content/:componentId",
) as RouteObject[];

/**
 * Our card request page.
 *
 * The menu follows the order of `RootRoute.children` (see PageNav), so this entry sits LAST and the
 * tab lands at the bottom of the menu.
 */
export const CardsRoute: RouteObject = {
  path: "cards",
  element: <RequestCard />,
};

/**
 * Message key and visibility flag per route, mirroring the stock `content.json`.
 *
 * Both are needed and neither is derivable: the label key is not the last path segment
 * (`verifiable-credentials` versus `verifiableCredentials`), and a realm that disables a feature
 * still has the route — the stock console hides the entry, it does not remove the page.
 */
export const menuEntries: { path: string; label: string; feature?: string }[] = [
  { path: "", label: "personalInfo" },
  { path: "account-security/signing-in", label: "signingIn" },
  { path: "account-security/device-activity", label: "deviceActivity" },
  { path: "account-security/linked-accounts", label: "linkedAccounts", feature: "isLinkedAccountsEnabled" },
  { path: "applications", label: "applications", feature: "isViewApplicationsEnabled" },
  { path: "verifiable-credentials", label: "verifiableCredentials", feature: "isOid4VciEnabled" },
  { path: "groups", label: "groups", feature: "isViewGroupsEnabled" },
  { path: "organizations", label: "organizations", feature: "isViewOrganizationsEnabled" },
  { path: "resources", label: "resources", feature: "isMyResourcesEnabled" },
  { path: "cards", label: "cards" },
];

export const RootRoute: RouteObject = {
  path: decodeURIComponent(new URL(environment.baseUrl).pathname),
  element: <App />,
  errorElement: <>Error</>,
  children: [...stockPages, CardsRoute],
};

export const routes: RouteObject[] = [RootRoute];
