import { useState } from "react";

import {
  chooseFile,
  chooseFiles,
  messageOf,
  sealMessage,
  unsealMessage,
} from "../core";
import type { Selection } from "../core";
import { Card, Field, PathPicker, SignerLine, StatusLine } from "../ui";
import type { Status } from "../ui";

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function Messages() {
  const [text, setText] = useState("");
  const [recipients, setRecipients] = useState<Selection[]>([]);
  const [sealed, setSealed] = useState("");
  const [sealStatus, setSealStatus] = useState<Status>({ kind: "idle" });

  const [incoming, setIncoming] = useState("");
  const [secret, setSecret] = useState<Selection | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [signer, setSigner] = useState<string | null>(null);
  const [openStatus, setOpenStatus] = useState<Status>({ kind: "idle" });

  const sealing = sealStatus.kind === "busy";
  const opening = openStatus.kind === "busy";

  async function addRecipients() {
    const added = await chooseFiles("public", true);
    setRecipients((current) => {
      const seen = new Set(current.map((entry) => entry.path));
      return [...current, ...added.filter((entry) => !seen.has(entry.path))];
    });
  }

  async function pickSecret() {
    const chosen = await chooseFile("secret");
    if (chosen) setSecret(chosen);
  }

  async function seal() {
    if (text.length === 0) {
      setSealStatus({ kind: "error", text: "Write a message first." });
      return;
    }
    if (recipients.length === 0) {
      setSealStatus({ kind: "error", text: "Add at least one recipient." });
      return;
    }
    setSealStatus({ kind: "busy", text: "Encrypting." });
    try {
      setSealed(
        await sealMessage(
          text,
          recipients.map((entry) => entry.id),
        ),
      );
      setSealStatus({
        kind: "ok",
        text: "Encrypted. Copy the block below into an email or chat.",
      });
    } catch (error) {
      setSealed("");
      setSealStatus({ kind: "error", text: messageOf(error) });
    }
  }

  async function unseal() {
    if (!secret) {
      setOpenStatus({ kind: "error", text: "Choose your secret key." });
      return;
    }
    setOpenStatus({ kind: "busy", text: "Decrypting and verifying." });
    setPlaintext(null);
    setSigner(null);
    try {
      const result = await unsealMessage(incoming, secret.id, passphrase || null);
      setPassphrase("");
      setPlaintext(result.text);
      setSigner(result.signer);
      setOpenStatus({ kind: "ok", text: "The message is intact." });
    } catch (error) {
      setPlaintext(null);
      setSigner(null);
      setOpenStatus({ kind: "error", text: messageOf(error) });
    }
  }

  return (
    <>
      <Card
        title="Encrypt a message"
        description="Turns text into a block you can paste anywhere. Only your recipients can read it."
      >
        <Field label="Message">
          <textarea
            rows={5}
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Write your message here"
          />
        </Field>
        <Field label="Recipients" hint="Their public keys.">
          <span className="picker">
            <input
              readOnly
              value={recipients.map((entry) => basename(entry.path)).join(", ")}
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
          onClick={seal}
          disabled={sealing}
        >
          Encrypt message
        </button>
        <StatusLine status={sealStatus} />
        {sealed ? (
          <>
            <textarea readOnly rows={8} value={sealed} />
            <button
              type="button"
              onClick={() => void navigator.clipboard.writeText(sealed)}
            >
              Copy
            </button>
          </>
        ) : null}
      </Card>

      <Card
        title="Read a message"
        description="Paste the encrypted block you received."
      >
        <Field label="Encrypted message">
          <textarea
            rows={6}
            value={incoming}
            onChange={(event) => setIncoming(event.target.value)}
            placeholder="----- BEGIN HIDE MESSAGE -----"
          />
        </Field>
        <PathPicker
          label="Your secret key"
          value={secret?.path ?? null}
          buttonText="Choose key"
          onPick={pickSecret}
        />
        <Field label="Passphrase" hint="Leave empty if the key has no passphrase.">
          <input
            type="password"
            value={passphrase}
            onChange={(event) => setPassphrase(event.target.value)}
          />
        </Field>
        <button
          type="button"
          className="primary"
          onClick={unseal}
          disabled={opening}
        >
          Read message
        </button>
        <StatusLine status={openStatus} />
        {plaintext !== null ? (
          <div className="result">
            <p className="field-label">Message:</p>
            <textarea readOnly rows={5} value={plaintext} />
            <SignerLine signer={signer} />
          </div>
        ) : null}
      </Card>
    </>
  );
}
