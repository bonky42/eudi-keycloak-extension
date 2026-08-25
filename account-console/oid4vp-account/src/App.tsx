import { Page, Spinner } from "@patternfly/react-core";
import { Header } from "./Header";
import { Suspense } from "react";
import { Outlet } from "react-router-dom";
import { PageNav } from "./PageNav";

/**
 * The console shell: our masthead, our navigation, and whatever the route renders.
 *
 * The scaffold ships a demo banner here (a Vite logo and an "extra content" heading). It is removed
 * on purpose: this console is the real one for this realm, not a sample, and a leftover placeholder
 * above every page is exactly the kind of thing nobody notices until a user asks about it.
 */
function App() {
  return (
    <Page header={<Header />} sidebar={<PageNav />} isManagedSidebar>
      <Suspense fallback={<Spinner />}>
        <Outlet />
      </Suspense>
    </Page>
  );
}

export default App;
