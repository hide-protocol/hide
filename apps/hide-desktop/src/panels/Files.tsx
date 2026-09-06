import { useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";

import { decryptFile, encryptFile, messageOf } from "../core";
import { Card, Field, PathPicker, StatusLine } from "../ui";
import type { Status } from "../ui";

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function Files() {
  const [input, setInput] = useState<string | null>(null);
  const [recipients, setRecipients] = useState<string[]>([]);
  const [encryptStatus, setEncryptStatus] = useState<Status>({ kind: "idle" });

  const [container, setContainer] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [decryptStatus, setDecryptStatus] = useState<Status>({ kind: "idle" });

  async function pickInput() {
    const chosen = await open({ multiple: false });
    if (typeof chosen === "string") setInput(chosen);
  }

  async function addRecipients() {
    const chosen = await open({
      multiple: true,
      filters: [{ name: "HIDE public key", extensions: ["hide-pub", "txt"] }],
    });
    const added = Array.isArray(chosen) ? chosen : typeof chosen === "string" ? [chosen] : [];
    // Keep the list unique so the same person is not added twice.
    setRecipients((current) => [...new Set([...current, ...added])]);
  }

  async function runEncrypt() {
    if (!input) {
      setEncryptStatus({ kind: "error", text: "Choose a file to encrypt." });
      return;
    }
    if (recipients.length === 0) {
      setEncryptStatus({ kind: "error", text: "Add at least one recipient." });
      return;
    }
    const output = await save({
      defaultPath: `${basename(input)}.hide`,
      filters: [{ name: "HIDE container", extensions: ["hide"] }],
    });
    if (!output) return;

    setEncryptStatus({ kind: "busy", text: "Encrypting." });
    try {
      setEncryptStatus({ kind: "ok", text: await encryptFile(input, recipients, output) });
    } catch (error) {
      setEncryptStatus({ kind: "error", text: messageOf(error) });
    }
  }

  async function pickContainer() {
    const chosen = await open({
      multiple: false,
      filters: [{ name: "HIDE container", extensions: ["hide"] }],
    });
    if (typeof chosen === "string") setContainer(chosen);
  }

  async function pickSecret() {
    const chosen = await open({
      multiple: false,
      filters: [{ name: "HIDE secret key", extensions: ["hide-key"] }],
    });
    if (typeof chosen === "string") setSecret(chosen);
  }

  async function runDecrypt() {
    if (!container || !secret) {
      setDecryptStatus({
        kind: "error",
        text: "Choose both the encrypted file and your secret key.",
      });
      return;
    }
    const suggested = basename(container).replace(/\.hide$/i, "");
    const output = await save({ defaultPath: suggested || "decrypted" });
    if (!output) return;

    setDecryptStatus({ kind: "busy", text: "Decrypting and verifying." });
    try {
      const text = await decryptFile(container, secret, passphrase || null, output);
      setPassphrase("");
      setDecryptStatus({ kind: "ok", text });
    } catch (error) {
      setDecryptStatus({ kind: "error", text: messageOf(error) });
    }
  }

  return (
    <>
      <Card
        title="Encrypt a file"
        description="Only the people you list will be able to open it."
      >
        <PathPicker
          label="File"
          value={input}
          buttonText="Choose file"
          onPick={pickInput}
        />
        <Field label="Recipients" hint="Their public keys. Up to 64.">
          <span className="picker">
            <input
              readOnly
              value={
                recipients.length === 0
                  ? ""
                  : recipients.map(basename).join(", ")
              }
              placeholder="Nobody yet"
            />
            <button type="button" onClick={addRecipients}>
              Add
            </button>
            {recipients.length > 0 ? (
              <button type="button" onClick={() => setRecipients([])}>
                Clear
              </button>
            ) : null}
          </span>
        </Field>
        <button type="button" className="primary" onClick={runEncrypt}>
          Encrypt
        </button>
        <StatusLine status={encryptStatus} />
      </Card>

      <Card
        title="Decrypt a file"
        description="The file is written only after its contents are verified as intact."
      >
        <PathPicker
          label="Encrypted file"
          value={container}
          buttonText="Choose file"
          onPick={pickContainer}
        />
        <PathPicker
          label="Your secret key"
          value={secret}
          buttonText="Choose key"
          onPick={pickSecret}
        />
        <Field
          label="Passphrase"
          hint="Leave empty if the key has no passphrase."
        >
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
          />
        </Field>
        <button type="button" className="primary" onClick={runDecrypt}>
          Decrypt
        </button>
        <StatusLine status={decryptStatus} />
      </Card>
    </>
  );
}
