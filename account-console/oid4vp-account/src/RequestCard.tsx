import {
  AccountEnvironment,
  Page,
  useEnvironment,
  usePromise,
} from "@keycloak/keycloak-account-ui";
import {
  Button,
  DataList,
  DataListAction,
  DataListCell,
  DataListItem,
  DataListItemCells,
  DataListItemRow,
  Spinner,
} from "@patternfly/react-core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

/**
 * One card this realm can issue, as returned by the server.
 *
 * Mirrors `OfferableCard` in the `oid4vp-login` extension. The server owns the rule of what counts
 * as a card — a client scope whose protocol is `oid4vc` and which carries a credential configuration
 * id — and this page never second-guesses it, so the two cannot drift apart.
 */
type OfferableCard = {
  displayName: string;
  configurationId: string;
};

/**
 * Either the cards or the reason we have none.
 *
 * Kept as one value on purpose: "the server did not answer" and "this realm issues nothing" are
 * unrelated situations, and a component that cannot tell them apart sends its reader looking in the
 * wrong place.
 */
type Catalog = { cards?: OfferableCard[]; error?: string };

const cardsBase = (env: AccountEnvironment) =>
  `${env.serverBaseUrl}/realms/${env.realm}/cards`;

export const RequestCard = () => {
  const { t } = useTranslation();
  const context = useEnvironment<AccountEnvironment>();
  const [catalog, setCatalog] = useState<Catalog>();

  usePromise<Catalog>(
    async (signal) => {
      try {
        const response = await fetch(`${cardsBase(context.environment)}/available`, {
          signal,
          headers: { Accept: "application/json" },
        });
        if (!response.ok) {
          return { error: `HTTP ${response.status}` };
        }
        return { cards: (await response.json()) as OfferableCard[] };
      } catch (e) {
        return { error: e instanceof Error ? e.message : String(e) };
      }
    },
    setCatalog,
  );

  const request = (card: OfferableCard) => {
    // A full page navigation, not a client-side route: the server grants the entitlement and then
    // redirects to /auth, which renders Keycloak's own offer page with the QR code. None of that
    // flow belongs to this console.
    window.location.href = `${cardsBase(context.environment)}/request?id=${encodeURIComponent(
      card.configurationId,
    )}`;
  };

  return (
    <Page title={t("cards")} description={t("cards.description")}>
      {!catalog ? (
        <Spinner aria-label={t("cards.loading")} />
      ) : catalog.error ? (
        <p>{t("cards.error", { reason: catalog.error })}</p>
      ) : catalog.cards!.length === 0 ? (
        <p>{t("cards.empty")}</p>
      ) : (
        <DataList aria-label={t("cards")}>
          {catalog.cards!.map((card) => (
            <DataListItem key={card.configurationId}>
              <DataListItemRow>
                <DataListItemCells
                  dataListCells={[
                    <DataListCell key="name">
                      <strong id={card.configurationId}>{card.displayName}</strong>
                      <div>{card.configurationId}</div>
                    </DataListCell>,
                  ]}
                />
                <DataListAction
                  aria-labelledby={card.configurationId}
                  id={`request-${card.configurationId}`}
                  aria-label={t("cards.request")}
                >
                  <Button
                    variant="secondary"
                    data-testid={`request-${card.configurationId}`}
                    onClick={() => request(card)}
                  >
                    {t("cards.request")}
                  </Button>
                </DataListAction>
              </DataListItemRow>
            </DataListItem>
          ))}
        </DataList>
      )}
    </Page>
  );
};
