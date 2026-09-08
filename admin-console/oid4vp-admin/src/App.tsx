import KeycloakAdminClient from "@keycloak/keycloak-admin-client";
import {
  AccessContextProvider,
  AdminEnvironment,
  AdminClientContext,
  ErrorBoundaryProvider,
  ErrorRenderer,
  Header,
  PageBreadCrumbs,
  PageNav,
  RealmContextProvider,
  RecentRealmsProvider,
  ServerInfoProvider,
  SubGroups,
  WhoAmIContextProvider,
  initAdminClient,
  useEnvironment,
} from "@keycloak/keycloak-admin-ui";
import {
  AlertProvider,
  ErrorBoundaryFallback,
  ErrorBoundaryProvider as SharedErrorBoundaryProvider,
  Help,
  mainPageContentId,
} from "@keycloak/keycloak-ui-shared";
import { Page, Spinner } from "@patternfly/react-core";
import { Suspense, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";

/**
 * The console shell: the stock header and navigation, and whatever the route renders.
 *
 * <p>The provider stack is assembled here rather than reused from the package's own root. That root
 * (`AdminUi`) is written for Keycloak's build, not for composition: mounting it produced "No
 * provider found for the 'AdminClientContext' context" and nothing else. The supported shape —
 * what `create-keycloak-theme --type admin` generates — is this: create the admin client yourself,
 * publish it, then stack the contexts the pages expect.</p>
 *
 * <p>Header and PageNav come from the package, so the menu is the real one and follows upstream
 * across versions. The scaffold ships its own PageNav because it builds a console with a single
 * page; ours carries every stock route, so re-deriving the menu here would mean owning it forever
 * and losing whatever upstream adds.</p>
 */
function App() {
  // AdminEnvironment is BaseEnvironment plus adminBaseUrl, consoleBaseUrl, masterRealm and
  // resourceVersion — the admin console can be served from a different host than the server it
  // administers, which is exactly this deployment's shape. The scaffold reaches for
  // AccountEnvironment here and does not compile; the published alias is this one.
  const { keycloak, environment } = useEnvironment<AdminEnvironment>();
  const [adminClient, setAdminClient] = useState<KeycloakAdminClient>();

  useEffect(() => {
    initAdminClient(keycloak, environment).then(setAdminClient).catch(console.error);
  }, [keycloak, environment]);

  // Every page below reads the admin client on mount, so there is nothing sensible to render
  // before it exists — and rendering anyway is what turns a slow start into an error screen.
  if (!adminClient) return <Spinner />;

  return (
    <AdminClientContext.Provider value={{ keycloak, adminClient }}>
      <ErrorBoundaryProvider>
        <RealmContextProvider>
          <ServerInfoProvider>
            <WhoAmIContextProvider>
              <RecentRealmsProvider>
                <AccessContextProvider>
                  <SubGroups>
                    {/*
                      mainContainerId: ScrollForm tracks which section is on screen by reading the
                      scrolling element BY ID, and gives up in silence when it is missing — the
                      jump links render, scroll on click, and never highlight. The id is
                      upstream's own constant, and the element it names is this one.
                    */}
                    <Page
                      header={<Header />}
                      sidebar={<PageNav />}
                      isManagedSidebar
                      breadcrumb={<PageBreadCrumbs />}
                      mainContainerId={mainPageContentId}
                    >
                      {/*
                        The same three providers a second time, from the OTHER copy of the shared
                        library. The package publishes a bundle that inlines its own copy, so the
                        AlertProvider and Help its KeycloakProvider mounts, and the error boundary
                        above, are readable only by its own components. A page written here reaches
                        the library directly and finds all three empty — useFetch and the "?" badge
                        throw outright on a missing provider. They belong at this level and not
                        inside the page: mounted lower they are torn down on every navigation,
                        taking the "provider created" toast with them.
                      */}
                      <SharedErrorBoundaryProvider>
                        <ErrorBoundaryFallback fallback={ErrorRenderer}>
                          <AlertProvider>
                            <Help>
                              <Suspense fallback={<Spinner />}>
                                <Outlet />
                              </Suspense>
                            </Help>
                          </AlertProvider>
                        </ErrorBoundaryFallback>
                      </SharedErrorBoundaryProvider>
                    </Page>
                  </SubGroups>
                </AccessContextProvider>
              </RecentRealmsProvider>
            </WhoAmIContextProvider>
          </ServerInfoProvider>
        </RealmContextProvider>
      </ErrorBoundaryProvider>
    </AdminClientContext.Provider>
  );
}

export default App;
