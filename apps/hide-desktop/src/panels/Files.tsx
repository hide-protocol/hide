import { useState } from "react";

import {
  chooseFile,
  chooseFiles,
  chooseSavePath,
  decryptFile,
  encryptFile,
  messageOf,
} from "../core";
import type { Opened, Selection } from "../core";
import { Card, Field, PathPicker, SignerLine, StatusLine } from "../ui";
import type { Status } from "../ui";

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function Files() {
  const [input, setInput] = useState<Selection | null>(null);
  const [recipients, setRecipients] = useState<Selection[]>([]);
  const [encryptStatus, setEncryptStatus] = useState<Status>({ kind: "idle" });

  const [container, setContainer] = useState<Selection | null>(null);
  const [secret, setSecret] = useState<Selection | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [decryptStatus, setDecryptStatus] = useState<Status>({ kind: "idle" });
  const [opened, setOpened] = useState<Opened | null>(null);

  const encrypting = encryptStatus.kind === "busy";
  const decrypting = decryptStatus.kind === "busy";

  async function pickInput() {
    const chosen = await chooseFile("any");
    if (chosen) setInput(chosen);
  }

  async function addRecipients() {
    const added = await chooseFiles("public", true);
    // Keyed by the path the user actually chose, so the same person is not
    // added twice even though every pick gets its own id.
    setRecipients((current) => {
      const seen = new Set(current.map((entry) => entry.path));
      return [...current, ...added.filter((entry) => !seen.has(entry.path))];
    });
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
    const output = await chooseSavePath(
      "container",
      `${basename(input.path)}.hide`,
    );
    if (!output) return;

    setEncryptStatus({ kind: "busy", text: "Encrypting." });
    try {
      setEncryptStatus({
        kind: "ok",
        text: await encryptFile(
          input.id,
          recipients.map((entry) => entry.id),
          output.id,
        ),
      });
    } catch (error) {
      setEncryptStatus({ kind: "error", text: messageOf(error) });
    }
  }

  async function pickContainer() {
    const chosen = await chooseFile("container");
    if (chosen) setContainer(chosen);
  }

  async function pickSecret() {
    const chosen = await chooseFile("secret");
    if (chosen) setSecret(chosen);
  }

  async function runDecrypt() {
    if (!container || !secret) {
      setDecryptStatus({
        kind: "error",
        text: "Choose both the encrypted file and your secret key.",
      });
      return;
    }
    const suggested = basename(container.path).replace(/\.hide$/i, "");
    const output = await chooseSavePath("any", suggested || "decrypted");
    if (!output) return;

    setDecryptStatus({ kind: "busy", text: "Decrypting and verifying." });
    setOpened(null);
    try {
      const result = await decryptFile(
        container.id,
        secret.id,
        passphrase || null,
        output.id,
      );
      setPassphrase("");
      setOpened(result);
      setDecryptStatus({
        kind: "ok",
        text: `Integrity verified; ${result.plaintext_len} bytes written.`,
      });
    } catch (error) {
      setOpened(null);
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
          value={input?.path ?? null}
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
                  : recipients.map((entry) => basename(entry.path)).join(", ")
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
        <button
          type="button"
          className="primary"
          onClick={runEncrypt}
          disabled={encrypting}
        >
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
          value={container?.path ?? null}
          buttonText="Choose file"
          onPick={pickContainer}
        />
        <PathPicker
          label="Your secret key"
          value={secret?.path ?? null}
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
        <button
          type="button"
          className="primary"
          onClick={runDecrypt}
          disabled={decrypting}
        >
          Decrypt
        </button>
        <StatusLine status={decryptStatus} />
        {opened ? (
          <div className="result">
            {opened.filename ? (
              <p>
                Original name: <code>{opened.filename}</code>
              </p>
            ) : null}
            <SignerLine signer={opened.signer} />
          </div>
        ) : null}
      </Card>
    </>
  );
}
