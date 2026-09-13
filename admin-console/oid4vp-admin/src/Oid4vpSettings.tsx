import type { ConfigPropertyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigInfoRepresentation";
import type IdentityProviderRepresentation from "@keycloak/keycloak-admin-client/lib/defs/identityProviderRepresentation";
import {
  FixedButtonsGroup,
  FormAccess,
  ViewHeader,
  useAdminClient,
  useConfirmDialog,
  useRealm,
  useServerInfo,
} from "@keycloak/keycloak-admin-ui";
import {
  KeycloakSpinner,
  ScrollForm,
  SelectControl,
  SwitchControl,
  TextControl,
  useAlerts,
  useFetch,
} from "@keycloak/keycloak-ui-shared";
import {
  ActionGroup,
  AlertVariant,
  Button,
  ButtonVariant,
  DropdownItem,
  PageSection,
  Text,
} from "@patternfly/react-core";
import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { Controller, FormProvider, useForm, useWatch } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { Link, useNavigate, useParams } from "react-router-dom";
import { CertificatePanel, type CertificateSummary } from "./CertificatePanel";
import type ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";
import { ConfigField } from "./ConfigFields";

const PROVIDER_ID = "oid4vp";

/** The key provider whose components can sign this provider's requests. */
const KEY_PROVIDER_ID = "oid4vp-verifier-key";
const KEY_COMPONENT_TYPE = "org.keycloak.keys.KeyProvider";
const SIGNING_KEY_REF = "signingKeyRef";


/**
 * Field ORDER and grouping — never which fields exist.
 *
 * <p>The server decides what exists; anything this list does not name still renders, under "Other
 * settings". A closed list here would reproduce what makes the stock form wrong: a property
 * declared in Java would vanish from the screen with nothing said. The counts happen to match
 * today, which is exactly how that bug installs itself unnoticed — it was written that way once,
 * and caught only because a field was deliberately added to see whether it disappeared.</p>
 *
 * <p>The split is the real one: what verifies a presentation, what identifies the holder behind
 * it, and what only matters when this Keycloak also issues its own credential.</p>
 */
/**
 * The switch that governs the issuance section, and why it is not a stored field.
 *
 * <p>"Issuing our own credential" is off exactly when {@code ownVct} is empty — the server already
 * says so, and adding a boolean to the configuration would create a second source of truth that can
 * disagree with the first. So the switch lives in the form only, derived on load and never sent.</p>
 *
 * <p>Turning it off CLEARS the four fields rather than merely hiding them: a credential type left
 * behind an invisible switch would still decide how a presentation is turned into a user, which is
 * the worst of both readings.</p>
 */
const ISSUANCE_SWITCH = "issueOwnCredential";
const ISSUANCE_FIELDS = [
  "ownVct",
  "ownIssuerAnchorsPem",
  "ownCredentialConfigId",
  "reissueBeforeSeconds",
];

type FormValues = IdentityProviderRepresentation & { [ISSUANCE_SWITCH]?: boolean };

const SECTIONS: { title: string; hint: string; fields: string[]; gated?: boolean }[] = [
  {
    title: "Verifying presentations",
    hint: "Everything below is needed before a wallet can be asked for anything at all.",
    fields: ["trustAnchorsPem", "signingKeyRef", "dcqlQueryJson", "ttlSeconds",
             "requestPurpose"],
  },
  {
    title: "Identifying the holder",
    hint: "How a verified presentation becomes a user. Every field here has a working default.",
    fields: ["matchingClaim", "subjectClaim", "subjectClaimByVct", "subjectPolicy"],
  },
  {
    title: "Issuing our own credential",
    // The switch below already says what "off" means, so the hint keeps only what the switch
    // cannot: the consequence of getting the anchors wrong once it is on.
    hint: "A credential type makes its issuer anchors mandatory: without them every card of that "
        + "type is refused, and that refusal ends the authentication rather than falling back to "
        + "another credential.",
    fields: ["ownVct", "ownIssuerAnchorsPem", "ownCredentialConfigId", "reissueBeforeSeconds"],
    gated: true,
  },
];

const OTHER_SECTION = {
  title: "Other settings",
  hint: "Declared by the server and not yet grouped. Nothing is hidden for being unrecognised.",
};

/**
 * The one sentence this page adds to what the server says: it answers the question raised by the
 * absence of the fields every other provider shows.
 */
const SUBTITLE =
  "This provider is a verifier, not an OAuth client: its identifier is derived from the signing "
  + "certificate below, so there is no client id or secret to configure.";

/**
 * The alert, help and error-boundary providers this page reads are mounted in App, from the copy of
 * the shared library a page written here can reach — the package's own are private to its bundle.
 * See the comment there.
 */
export const Oid4vpSettings = ({ mode }: { mode: "add" | "edit" }) => {
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const serverInfo = useServerInfo();
  const navigate = useNavigate();
  const { alias: aliasParam } = useParams<{ alias: string }>();
  const { t } = useTranslation();
  const { addAlert, addError } = useAlerts();

  const [provider, setProvider] = useState<IdentityProviderRepresentation>();
  const [keys, setKeys] = useState<ComponentRepresentation[]>([]);
  const [certificate, setCertificate] = useState<CertificateSummary | "none" | "broken">();

  const form = useForm<FormValues>({
    defaultValues: { alias: PROVIDER_ID, enabled: true, config: {}, [ISSUANCE_SWITCH]: false },
    mode: "onChange",
  });
  const {
    control,
    getValues,
    handleSubmit,
    reset,
    setValue,
    formState: { isDirty },
  } = form;

  /** Labels, help texts, types and `required` all come from the server; nothing is restated here. */
  const descriptors = useMemo<ConfigPropertyRepresentation[]>(() => {
    const types = (serverInfo?.componentTypes ?? {})[
      "org.keycloak.broker.provider.IdentityProvider"
    ] as { id: string; properties?: ConfigPropertyRepresentation[] }[] | undefined;
    return types?.find((type) => type.id === PROVIDER_ID)?.properties ?? [];
  }, [serverInfo]);

  useFetch(
    () =>
      mode === "edit" && aliasParam
        ? adminClient.identityProviders.findOne({ alias: aliasParam })
        : Promise.resolve(undefined),
    (found) => {
      if (mode !== "edit") return;
      if (!found) throw new Error(t("notFound"));
      reset({ ...found, [ISSUANCE_SWITCH]: !!found.config?.ownVct });
      setProvider(found);
    },
    [mode, aliasParam],
  );

  // Both routes render this same component, so React keeps it mounted when one replaces the other
  // and the form keeps whatever the previous page put in it. Reaching "Add provider" from an edit
  // page showed the edited provider's values — including, since the selector exists, a key
  // belonging to another realm.
  useEffect(() => {
    if (mode === "add") {
      reset({ alias: PROVIDER_ID, enabled: true, config: {}, [ISSUANCE_SWITCH]: false });
      setProvider(undefined);
      setCertificate(undefined);
    }
  }, [mode, realm, reset]);

  // The keys this provider may name. Fetched rather than declared: the descriptor knows the field
  // is a string, only the realm knows which strings are legal.
  useFetch(
    () => adminClient.components.find({ type: KEY_COMPONENT_TYPE }),
    (found) => setKeys(found.filter((c) => c.providerId === KEY_PROVIDER_ID)),
    // The realm is a dependency: keys belong to one, and a stale list would offer a key the realm
    // on screen does not have.
    [realm],
  );

  const keyRef = useWatch({ control, name: `config.${SIGNING_KEY_REF}` as const });

  // What the chosen certificate actually says, computed by the server. The client_id below is the
  // one field on this page nobody can check by eye, and deriving it here instead would be a second
  // implementation of a value the request object already produces.
  useFetch(
    async () => {
      if (mode !== "edit" || !aliasParam || !keyRef) return undefined;
      // Plain fetch: this client exposes one resource object per stock endpoint and no generic
      // call, and adding a resource to it would mean patching the package.
      const response = await fetch(
        `${adminClient.baseUrl}/admin/realms/${realm}`
          + `/oid4vp/providers/${aliasParam}/signing-certificate`,
        { headers: { Authorization: `Bearer ${await adminClient.getAccessToken()}` } },
      );
      if (response.status === 404) return "none" as const;
      if (!response.ok) return "broken" as const;
      return (await response.json()) as CertificateSummary;
    },
    (summary) => setCertificate(summary),
    [realm, mode, aliasParam, keyRef],
  );

  const issuing = useWatch({ control, name: ISSUANCE_SWITCH });
  const wasIssuing = useRef(issuing);
  useEffect(() => {
    // Only on the transition, and only downwards: clearing on every render would fight the load.
    // Back to the SERVER'S default rather than to empty, so that switching off and on again leaves
    // the section as an untouched one would look — the control's own defaultValue is applied when
    // the field first registers and never again.
    if (wasIssuing.current && !issuing) {
      ISSUANCE_FIELDS.forEach((field) => {
        const declared = descriptors.find((d) => d.name === field)?.defaultValue;
        setValue(`config.${field}`, declared ?? "", { shouldDirty: true });
      });
    }
    wasIssuing.current = issuing;
  }, [issuing, setValue, descriptors]);

  const toList = `/${realm}/identity-providers`;

  const save = async (values?: FormValues) => {
    const { [ISSUANCE_SWITCH]: _switch, ...submitted } = values ?? getValues();
    // An untouched optional field arrives as "" and must not be stored: `ownVct` set to the empty
    // string is not the same statement as `ownVct` absent, and the cross-field rule in
    // Oid4vpIdentityProviderConfig reads presence, not truthiness.
    const config = Object.fromEntries(
      Object.entries(submitted.config ?? {}).filter(
        ([, value]) => String(value ?? "").trim() !== "",
      ),
    );
    const payload = { ...submitted, providerId: PROVIDER_ID, config };

    try {
      if (mode === "add") {
        await adminClient.identityProviders.create(payload);
        addAlert(t("createIdentityProviderSuccess"), AlertVariant.success);
        navigate(`${toList}/${PROVIDER_ID}/${payload.alias}/settings`);
      } else {
        const alias = provider?.alias ?? aliasParam!;
        await adminClient.identityProviders.update({ alias }, { ...payload, alias });
        reset(submitted);
        addAlert(t("updateSuccessIdentityProvider"), AlertVariant.success);
      }
    } catch (error) {
      // NetworkError carries the server's own sentence as its message — the admin client builds it
      // from the response's `errorMessage`. That is what Oid4vpIdentityProviderConfig.validate
      // writes: it names the field to fill and says what breaks without it. Paraphrasing would
      // blur the one message that helps.
      addError(
        mode === "add" ? "createIdentityProviderError" : "updateErrorIdentityProvider",
        error,
      );
    }
  };

  // Turning the provider off is asked about, exactly as the console asks for every other provider:
  // a disabled broker stops every login that goes through it, and the switch is one stray click away
  // from the kebab menu.
  const [pendingDisable, setPendingDisable] = useState<(() => void) | null>(null);
  const [toggleDisableDialog, DisableConfirm] = useConfirmDialog({
    titleKey: "disableProvider",
    messageKey: t("disableConfirmIdentityProvider", { provider: aliasParam }),
    continueButtonLabel: "disable",
    onConfirm: () => pendingDisable?.(),
  });

  const [toggleDeleteDialog, DeleteConfirm] = useConfirmDialog({
    titleKey: "deleteProvider",
    messageKey: t("deleteConfirmIdentityProvider", { provider: aliasParam }),
    continueButtonLabel: "delete",
    continueButtonVariant: ButtonVariant.danger,
    onConfirm: async () => {
      try {
        await adminClient.identityProviders.del({ alias: aliasParam! });
        addAlert(t("deletedSuccessIdentityProvider"), AlertVariant.success);
        navigate(toList);
      } catch (error) {
        addError("deleteErrorIdentityProvider", error);
      }
    },
  });

  if (mode === "edit" && !provider) return <KeycloakSpinner />;

  // Which fields go where is decided BEFORE anything is rendered, because two things depend on the
  // answer: a group with nothing in it must not print a heading, and the buttons belong to the last
  // group that survives. Deciding it inside the render is how they ended up attached to "Other
  // settings" — always last, and always empty once the named groups have taken everything.
  const placed = new Set<string>();
  const groups = [
    ...SECTIONS,
    { ...OTHER_SECTION, fields: descriptors.map((d) => d.name!) },
  ]
    .map(({ title, hint, fields, gated }) => {
      const rows = fields
        .map((field) => descriptors.find((d) => d.name === field))
        .filter((d): d is ConfigPropertyRepresentation => !!d && !placed.has(d.name!));
      rows.forEach((d) => placed.add(d.name!));
      return { title, hint, rows, gated };
    })
    .filter(({ rows }) => rows.length > 0);

  const buttons =
    mode === "add" ? (
      <ActionGroup>
        <Button variant="primary" type="submit" data-testid="createProvider">
          {t("add")}
        </Button>
        <Button
          variant="link"
          data-testid="cancel"
          component={(props) => <Link {...props} to={toList} />}
        >
          {t("cancel")}
        </Button>
      </ActionGroup>
    ) : (
      <FixedButtonsGroup
        name="oid4vp-details"
        isSubmit
        reset={() => reset(provider)}
        isDisabled={!isDirty}
      />
    );

  const formPanel = (children: ReactNode) => (
    <FormAccess
      role="manage-identity-providers"
      isHorizontal
      className="pf-v5-u-py-lg"
      onSubmit={handleSubmit(save)}
    >
      {children}
    </FormAccess>
  );

  const sections = [
    {
      title: t("generalSettings"),
      panel: formPanel(
        <TextControl
          name="alias"
          label={t("alias")}
          labelIcon={t("aliasHelp")}
          isDisabled={mode === "edit"}
          rules={{ required: t("required") }}
        />,
      ),
    },
    ...groups.map(({ title, hint, rows, gated }, index) => ({
      title,
      panel: formPanel(
        <>
          <Text className="pf-v5-u-pb-lg">{hint}</Text>
          {gated && (
            <SwitchControl
              name={ISSUANCE_SWITCH}
              label="Issue our own credential"
              labelIcon={
                "Off, the provider only recognises credentials issued elsewhere. On, it also "
                + "issues one — and the fields below decide which, and who may sign it."
              }
              labelOn={t("on")}
              labelOff={t("off")}
            />
          )}
          {(!gated || issuing) &&
            rows.map((property) => (
              <ConfigField
                key={property.name}
                property={property}
                // The server refuses a credential type without its anchors. Saying so on the field
                // is the same rule read forwards: the form marks what the server would reject.
                isRequired={
                  property.name === "ownIssuerAnchorsPem" ? !!issuing : undefined
                }
                // A free-text component id is a value nobody can type correctly. The realm knows
                // the answers; the descriptor cannot.
                render={
                  property.name === SIGNING_KEY_REF
                    ? (common) => (
                        <SelectControl
                          {...common}
                          options={keys.map((key) => ({
                            key: key.id!,
                            value: key.name ?? key.id!,
                          }))}
                          controller={{ defaultValue: "", rules: common.rules }}
                        />
                      )
                    : undefined
                }
              />
            ))}
          {rows.some((property) => property.name === SIGNING_KEY_REF) && (
            <CertificatePanel keys={keys} summary={certificate} />
          )}
          {index === groups.length - 1 && buttons}
        </>,
      ),
    })),
  ];

  return (
    <FormProvider {...form}>
      <DeleteConfirm />
      <DisableConfirm />
      {mode === "edit" ? (
        <Controller
          name="enabled"
          control={control}
          defaultValue={true}
          render={({ field }) => (
            <ViewHeader
              titleKey={`OID4VP Wallet — ${provider?.alias}`}
              subKey={SUBTITLE}
              divider={false}
              isEnabled={field.value || false}
              onToggle={(value) => {
                const apply = () => {
                  field.onChange(value);
                  save({ ...getValues(), enabled: value });
                };
                if (value) return apply();
                setPendingDisable(() => apply);
                toggleDisableDialog();
              }}
              dropdownItems={[
                <DropdownItem key="delete" onClick={() => toggleDeleteDialog()}>
                  {t("delete")}
                </DropdownItem>,
              ]}
            />
          )}
        />
      ) : (
        <ViewHeader
          titleKey="Add OID4VP Wallet provider"
          subKey={SUBTITLE}
          divider={false}
        />
      )}

      {/*
        Bottom padding, and only in edit mode: FixedButtonsGroup is `position: fixed; bottom: 0` and
        reserves no room for itself, so the last control of the last section sits under it with no
        scroll left to reach it. Upstream never sees this because its final section is long.
      */}
      <PageSection
        variant="light"
        className={mode === "edit" ? "pf-v5-u-p-0 pf-v5-u-pb-4xl" : "pf-v5-u-p-0"}
      >
        <ScrollForm
          label={t("jumpToSection")}
          className="pf-v5-u-px-lg"
          sections={sections}
        />
      </PageSection>
    </FormProvider>
  );
};
