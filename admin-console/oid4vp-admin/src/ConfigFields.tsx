import type { ConfigPropertyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigInfoRepresentation";
import {
  SelectControl,
  SwitchControl,
  TextAreaControl,
  TextControl,
} from "@keycloak/keycloak-ui-shared";
import { useTranslation } from "react-i18next";

/**
 * One server-declared property, rendered with the console's own control for its type.
 *
 * <p>This is a local stand-in for the package's {@code DynamicComponents}, which does exactly this
 * and is exported — but cannot be used from here. {@code @keycloak/keycloak-admin-ui} is published
 * as a bundle that INLINES both {@code @keycloak/keycloak-ui-shared} and {@code react-hook-form}
 * (its only externals are react, react-dom, react-i18next and react-router-dom). Its components
 * therefore read a form context object that no {@code FormProvider} reachable from here can write
 * to: a page owning its form has to build the fields from the copy of the shared library it can
 * reach. Everything context-free — {@code ViewHeader}, {@code FormAccess}, {@code ScrollForm} —
 * still comes from the package.</p>
 *
 * <p>Three behaviours differ from the package's own dispatcher, all deliberate:</p>
 * <ul>
 *   <li>Its {@code Text} case renders {@code <FormGroup required={...}>}, and PatternFly's prop is
 *       {@code isRequired} — so a required text area shows no asterisk upstream. Every required
 *       field of this provider is a text area. {@code TextAreaControl} derives the marker from
 *       {@code rules.required}, so it is stated once, here.</li>
 *   <li>An unrecognised type is logged to the console and dropped upstream. Silently losing a field
 *       the server declares is the defect this whole page exists to avoid, so it is shown instead,
 *       read-only and named.</li>
 * </ul>
 */

/** The form path a property is bound to — the shape the identity-provider API expects back. */
export const configPath = (name: string) => `config.${name}`;

/**
 * PEM bundles and DCQL documents are read character by character, and misread otherwise: a wrapped
 * base64 line or a stray brace has to be visible. The family is PatternFly's own monospace token,
 * so this borrows the design system's font rather than choosing one.
 */
const MONOSPACE = { fontFamily: "var(--pf-v5-global--FontFamily--monospace)" };

export const ConfigField = ({
  property,
  isRequired,
  render,
}: {
  property: ConfigPropertyRepresentation;
  /** Overrides the server's flag for a rule the server states across two fields, not on one. */
  isRequired?: boolean;
  /**
   * Rendered instead of the type's default control, for a field whose values this page can
   * enumerate and the descriptor cannot. It receives the label, help text and required marker the
   * server declares, so an override changes the control and never what the field says it is.
   */
  render?: (common: {
    name: string;
    label: string;
    labelIcon?: string;
    rules: { required?: string };
  }) => JSX.Element;
}) => {
  const { t, i18n } = useTranslation();
  const name = property.name!;

  // A server string is either a message-bundle key or literal text, and nothing marks which. Running
  // literal text through t() is not harmless: i18next reads ":" as a namespace separator, so a help
  // text such as "… e.g. urn:eudi:pid:1=sub" comes back truncated at the first colon. This is the
  // package's own guard, taken from ViewHeader: translate only what the bundle actually declares.
  const translate = (value?: string) =>
    value && i18n.exists(value) ? t(value) : value;

  const label = translate(property.label) || name;
  const labelIcon = translate(property.helpText);
  // Passed ONLY when the server declares one. PatternFly's TextArea decides whether it is a
  // controlled element with `typeof defaultValue !== "string" && { value }` — so the empty string
  // is enough to drop `value` altogether, and the field stays blank forever however the form is
  // filled. Text inputs have no such rule, which is why an edit page showed every text box filled
  // and every text area empty.
  //
  // The rule is stated as the SHORT form, and only when the field really is required. TextControl
  // unwraps the long form `{ value, message }` through getRuleValue, but TextAreaControl reads
  // `!!rules.required` — and an object is always true, so `{ value: false }` decorates an optional
  // field with an asterisk. The short form means the same thing to react-hook-form and survives
  // both readings.
  const rules = (isRequired ?? property.required) ? { required: t("required") } : {};
  const common = {
    name: configPath(name),
    label,
    labelIcon,
    ...(property.defaultValue != null ? { defaultValue: property.defaultValue } : {}),
  };

  if (render) {
    return render({ name: configPath(name), label, labelIcon, rules });
  }

  switch (property.type) {
    case "Text":
      return <TextAreaControl {...common} rules={rules} rows={10} style={MONOSPACE} />;

    case "List":
      return (
        <SelectControl
          {...common}
          options={property.options ?? []}
          controller={{ defaultValue: property.defaultValue ?? "", rules }}
        />
      );

    case "boolean":
      return (
        <SwitchControl
          {...common}
          labelOn={t("on")}
          labelOff={t("off")}
          stringify
        />
      );

    case "String":
    case "Integer":
    case "Number":
      return (
        <TextControl
          {...common}
          rules={rules}
          data-testid={name}
          type={property.type === "String" ? "text" : "number"}
        />
      );

    default:
      return (
        <TextControl
          {...common}
          data-testid={name}
          isDisabled
          helperText={`This page cannot edit a field of type "${property.type}" yet. `
            + `Its value is shown as stored; use the generic provider form to change it.`}
        />
      );
  }
};
