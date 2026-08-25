import {
  Nav,
  NavItem,
  NavList,
  PageSidebar,
  PageSidebarBody,
} from "@patternfly/react-core";
import { AccountEnvironment, useEnvironment } from "@keycloak/keycloak-account-ui";
import { MouseEvent as ReactMouseEvent } from "react";
import { useTranslation } from "react-i18next";
import { useHref, useLinkClickHandler, useLocation } from "react-router-dom";
import { menuEntries } from "./routes";

const NavLink = ({
  path,
  label,
}: {
  path: string;
  label: string;
}) => {
  const href = useHref(path);
  const handleClick = useLinkClickHandler(path);
  const { pathname } = useLocation();
  // Compare against the resolved href, not the raw path: the console is mounted under
  // /realms/{realm}/account/, so a bare path never matches the location.
  const isActive = pathname === href || (path !== "" && pathname.startsWith(href));

  return (
    <NavItem
      to={href}
      isActive={isActive}
      onClick={(e) =>
        handleClick(e as unknown as ReactMouseEvent<HTMLAnchorElement, MouseEvent>)
      }
    >
      {label}
    </NavItem>
  );
};

export const PageNav = () => {
  const { t } = useTranslation();
  const { environment } = useEnvironment<AccountEnvironment>();

  // A realm that disables a feature keeps the route but hides the entry — the same rule the stock
  // console applies through `isVisible` in its content.json. Without this, a realm sees tabs for
  // things it does not have: observed in production on 2026-08-17, where Groups and Resources
  // appeared out of nowhere.
  const visible = menuEntries.filter(
    (entry) => !entry.feature || environment.features[entry.feature as keyof typeof environment.features],
  );

  return (
    <PageSidebar>
      <PageSidebarBody>
        <Nav>
          <NavList>
            {visible.map((entry) => (
              <NavLink key={entry.path} path={entry.path} label={t(entry.label)} />
            ))}
          </NavList>
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );
};
