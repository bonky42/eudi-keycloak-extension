import type { AdminEnvironment } from "@keycloak/keycloak-admin-ui";
import { getInjectedEnvironment } from "@keycloak/keycloak-ui-shared";

/**
 * The values the server writes into index.ftl as a JSON island.
 *
 * AdminEnvironment is the published alias for the admin console's own shape: BaseEnvironment plus
 * adminBaseUrl, consoleBaseUrl, masterRealm and resourceVersion. The root route needs
 * consoleBaseUrl — hard-coding "/admin/{realm}/console/" would break the day a deployment sets a
 * different http-relative-path, or serves the console from its own host.
 */
export const environment = getInjectedEnvironment<AdminEnvironment>();
