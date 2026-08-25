import {
  Dropdown,
  DropdownItem,
  DropdownList,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  PageToggleButton,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from "@patternfly/react-core";
import { BarsIcon } from "@patternfly/react-icons";
import { AccountEnvironment, useEnvironment } from "@keycloak/keycloak-account-ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";

/**
 * Our own masthead, instead of the `Header` exported by `@keycloak/keycloak-account-ui`.
 *
 * <b>Why not theirs.</b> That package bundles its own copy of PatternFly, so its masthead — and the
 * sidebar toggle inside it — drives the PatternFly context of THAT copy, while our `Page` and
 * `PageSidebar` come from ours. Two instances, two React contexts: pressing the toggle flips a state
 * our sidebar never hears about.
 *
 * The symptom only appears below the mobile breakpoint, where the sidebar collapses and the toggle
 * becomes the only way to reach the menu — reported from a phone on 2026-08-18, and reproduced at a
 * 390 px viewport: the button is there, the links are in the DOM, and the sidebar stays at width 0
 * whatever you press.
 *
 * Owning ~60 lines of masthead keeps every piece of the console in a single PatternFly instance,
 * which is the only way the managed sidebar can work at all.
 */
export const Header = () => {
  const { t } = useTranslation();
  const { keycloak, environment } = useEnvironment<AccountEnvironment>();
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const username =
    keycloak.idTokenParsed?.preferred_username ?? keycloak.idTokenParsed?.name ?? "";

  return (
    <Masthead>
      <MastheadToggle>
        <PageToggleButton variant="plain" aria-label={t("navigation")}>
          <BarsIcon />
        </PageToggleButton>
      </MastheadToggle>
      <MastheadMain>
        <MastheadBrand>{environment.realm}</MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isFullHeight isStatic>
          <ToolbarContent>
            <ToolbarItem align={{ default: "alignRight" }}>
              <Dropdown
                isOpen={userMenuOpen}
                onOpenChange={setUserMenuOpen}
                onSelect={() => setUserMenuOpen(false)}
                toggle={(ref) => (
                  <MenuToggle
                    ref={ref}
                    onClick={() => setUserMenuOpen(!userMenuOpen)}
                    isExpanded={userMenuOpen}
                  >
                    {username}
                  </MenuToggle>
                )}
              >
                <DropdownList>
                  <DropdownItem
                    key="signOut"
                    onClick={() => keycloak.logout({ redirectUri: environment.baseUrl })}
                  >
                    {t("signOut")}
                  </DropdownItem>
                </DropdownList>
              </Dropdown>
            </ToolbarItem>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );
};
