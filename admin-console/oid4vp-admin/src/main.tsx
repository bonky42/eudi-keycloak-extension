import "@patternfly/react-core/dist/styles/base.css";
// The utility classes — pf-v5-u-py-lg, pf-v5-u-p-0, every spacing helper the console sprinkles
// through its own components — are NOT in base.css and not in the admin UI stylesheet either.
// They ship separately, and without this line every one of them is inert: the page still
// renders, only spaced wrong, everywhere, with nothing to show for it in the console.
import "@patternfly/patternfly/patternfly-addons.css";
// The package ships its stylesheet as a separate entry and its bundle does not pull it in:
// without this import the console renders with PatternFly's defaults only, and everything the
// admin UI styles itself — section panels, the fixed save bar — loses its rules silently.
import "@keycloak/keycloak-admin-ui/styles.css";

import { KeycloakProvider } from "@keycloak/keycloak-admin-ui";
import React from "react";
import ReactDOM from "react-dom/client";
import { createHashRouter, RouterProvider } from "react-router-dom";
import { environment } from "./environment";
import { i18n } from "./i18n";
import { routes } from "./routes";

// Hash routing, as upstream does it. The console's URLs read
// `/admin/{realm}/console/#/{realm}/…`, and the stock routes are declared ABSOLUTE
// (`/:realm/authentication`); a history router rooted at consoleBaseUrl rejects them outright —
// "an absolute child route path must start with the combined path of all its parent routes".
const router = createHashRouter(routes);

i18n.init().then(() => {
  ReactDOM.createRoot(document.getElementById("app")!).render(
    <React.StrictMode>
      <KeycloakProvider environment={environment}>
        <RouterProvider router={router} />
      </KeycloakProvider>
    </React.StrictMode>
  );
});
