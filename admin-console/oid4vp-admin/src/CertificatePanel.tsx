import type ComponentRepresentation from "@keycloak/keycloak-admin-client/lib/defs/componentRepresentation";
import {
  Alert,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Label,
} from "@patternfly/react-core";

/** What GET .../signing-certificate answers. Mirrors CertificateSummary on the server. */
export type CertificateSummary = {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  clientId: string;
  keyType: string;
  curve: string;
  notYetValid: boolean;
  expired: boolean;
};

const MONOSPACE = { fontFamily: "var(--pf-v5-global--FontFamily--monospace)" };

/**
 * Read, not edited. Set off on its own ground because everything above it is a field an
 * administrator fills in and this is the server answering back — laid flat among the inputs it read
 * as one more of them.
 */
const READ_ONLY_BLOCK = {
  background: "var(--pf-v5-global--BackgroundColor--200)",
  border: "1px solid var(--pf-v5-global--BorderColor--100)",
  // The rule down the left is the console's own mark for "this block, not the ones around it" —
  // the same one the jump-to-section list puts beside the section you are in.
  borderInlineStart: "3px solid var(--pf-v5-global--primary-color--100)",
  padding: "var(--pf-v5-global--spacer--md)",
};

const day = (iso: string) => {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? iso
    : parsed.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

/**
 * What the chosen signing key actually is, in the words of the certificate it carries.
 *
 * <p>The one line that earns this panel is the verifier identifier. It is the SHA-256 of the
 * certificate's DER, it is what a wallet compares the request's {@code x5c} against, and it is the
 * only thing on this form that cannot be checked by eye. It is <b>not computed here</b>: the server
 * derives it with the same call the request object makes, so this cannot describe one certificate
 * while a wallet is shown another.</p>
 *
 * <p>The rest is in the certificate for anyone willing to run {@code openssl x509 -text}. Not having
 * to is the point.</p>
 */
export const CertificatePanel = ({
  keys,
  summary,
}: {
  keys: ComponentRepresentation[];
  summary?: CertificateSummary | "none" | "broken";
}) => {
  // No key in the realm at all is a different problem from no key chosen, and it has a different
  // answer: one is a choice not yet made, the other is a thing that has to be created first.
  if (keys.length === 0) {
    return (
      <Alert
        isInline
        variant="warning"
        title="This realm has no OID4VP verifier key"
        className="pf-v5-u-mt-md"
      >
        Add one under Realm settings → Keys, with provider <b>oid4vp-verifier-key</b>, then choose it
        above. The key and its certificate live there rather than here: a value held in this
        provider is served back by the administration API and recorded in the admin event log.
      </Alert>
    );
  }

  if (summary === undefined || summary === "none") {
    return (
      <div className="pf-v5-u-mt-md pf-v5-u-color-200" style={READ_ONLY_BLOCK}>
        Choose a key above and this panel will say what its certificate is — who it names, who
        signed it, how long it lasts, and the identifier wallets are told.
      </div>
    );
  }

  if (summary === "broken") {
    return (
      <Alert
        isInline
        variant="danger"
        title="This provider names a key it cannot sign with"
        className="pf-v5-u-mt-md"
      >
        The key it points at is gone, or carries no certificate. Until it is corrected, every login
        through this provider fails — and the wallet's refusal names none of this.
      </Alert>
    );
  }

  const state = summary.expired
    ? { color: "red" as const, text: `Expired ${day(summary.notAfter)}` }
    : summary.notYetValid
      ? { color: "orange" as const, text: `Not valid until ${day(summary.notBefore)}` }
      : { color: "green" as const, text: `In force until ${day(summary.notAfter)}` };

  return (
    <div className="pf-v5-u-mt-md" style={READ_ONLY_BLOCK}>
      <div
        className="pf-v5-u-mb-md"
        style={{
          fontWeight: "var(--pf-v5-global--FontWeight--bold)",
          color: "var(--pf-v5-global--Color--200)",
        }}
      >
        What this key&apos;s certificate says
      </div>
      <DescriptionList isHorizontal termWidth="14rem">
        <DescriptionListGroup>
          <DescriptionListTerm>Announced to wallets</DescriptionListTerm>
          <DescriptionListDescription>
            <div style={{ ...MONOSPACE, wordBreak: "break-all" }}>{summary.clientId}</div>
          </DescriptionListDescription>
        </DescriptionListGroup>

        <DescriptionListGroup>
          <DescriptionListTerm>Validity</DescriptionListTerm>
          <DescriptionListDescription>
            <Label color={state.color}>{state.text}</Label>
          </DescriptionListDescription>
        </DescriptionListGroup>

        <DescriptionListGroup>
          <DescriptionListTerm>Subject</DescriptionListTerm>
          <DescriptionListDescription style={MONOSPACE}>
            {summary.subject}
          </DescriptionListDescription>
        </DescriptionListGroup>

        <DescriptionListGroup>
          <DescriptionListTerm>Issued by</DescriptionListTerm>
          <DescriptionListDescription style={MONOSPACE}>
            {summary.issuer}
          </DescriptionListDescription>
        </DescriptionListGroup>

        <DescriptionListGroup>
          <DescriptionListTerm>Key</DescriptionListTerm>
          <DescriptionListDescription style={MONOSPACE}>
            {summary.keyType}, {summary.curve}
          </DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
    </div>
  );
};
