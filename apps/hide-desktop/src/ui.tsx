import type { ReactNode } from "react";

export type Status =
  | { kind: "idle" }
  | { kind: "busy"; text: string }
  | { kind: "ok"; text: string }
  | { kind: "error"; text: string };

export function StatusLine({ status }: { status: Status }) {
  if (status.kind === "idle") return null;
  return (
    <p
      className={`status status-${status.kind}`}
      role={status.kind === "error" ? "alert" : "status"}
    >
      {status.kind === "busy" ? "Working… " : null}
      {status.text}
    </p>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

/** A file path plus the button that chose it, shown as one unit. */
export function PathPicker({
  label,
  hint,
  value,
  buttonText,
  onPick,
}: {
  label: string;
  hint?: string;
  value: string | null;
  buttonText: string;
  onPick: () => void;
}) {
  return (
    <Field label={label} hint={hint}>
      <span className="picker">
        <input readOnly value={value ?? ""} placeholder="No file chosen" />
        <button type="button" onClick={onPick}>
          {buttonText}
        </button>
      </span>
    </Field>
  );
}

export function Card({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="card">
      <h2>{title}</h2>
      <p className="card-description">{description}</p>
      {children}
    </section>
  );
}

/**
 * Who signed what just opened, in the words the CLI uses. A verified signature
 * is reported as a fingerprint and never as a name: nothing ties a key to a
 * person, so the reader is told to check the key against one they trust.
 */
export function SignerLine({ signer }: { signer: string | null }) {
  if (!signer) {
    return (
      <p className="status status-muted">
        Integrity verified, but the sender is <strong>not authenticated</strong>:
        anyone holding your public key could have encrypted this.
      </p>
    );
  }
  return (
    <p className="status status-ok">
      Signed by key <code>{signer}</code>. Check that key against one you
      already trust; HIDE does not.
    </p>
  );
}
