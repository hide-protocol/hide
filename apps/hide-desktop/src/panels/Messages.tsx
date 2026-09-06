import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { messageOf, sealMessage, unsealMessage } from "../core";
import { Card, Field, PathPicker, StatusLine } from "../ui";
import type { Status } from "../ui";

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function Messages() {
  const [text, setText] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const [sealed, setSealed] = useState("");
  const [sealStatus, setSealStatus] = useState<Status>({ kind: "idle" });

  const [incoming, setIncoming] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [openStatus, setOpenStatus] = useState<Status>({ kind: "idle" });

  async function addRecipients() {
    const chosen = await open({
      multiple: true,
      filters: [{ name: "HIDE public key", extensions: ["hide-pub", "txt"] }],
    });
    const added = Array.isArray(chosen) ? chosen : typeof chosen === "string" ? [chosen] : [];
    setRecipients((current) => [...new Set([...current, ...added])]);
  }

  async function pickSecret() {
    const chosen = await open({
      multiple: false,
      filters: [{ name: "HIDE secret key", extensions: ["hide-key"] }],
    });
    if (typeof chosen === "string") setSecret(chosen);
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
      setSealed(await sealMessage(text, recipients));
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
    try {
      const result = await unsealMessage(incoming, secret, passphrase || null);
      setPassphrase("");
      setPlaintext(result);
      setOpenStatus({
        kind: "ok",
        text: "The message is intact. HIDE cannot confirm who sent it.",
      });
    } catch (error) {
      setPlaintext(null);
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
              value={recipients.map(basename).join(", ")}
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
        <button type="button" className="primary" onClick={seal}>
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
          value={secret}
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
        <button type="button" className="primary" onClick={unseal}>
          Read message
        </button>
        <StatusLine status={openStatus} />
        {plaintext !== null ? (
          <div className="result">
            <p className="field-label">Message:</p>
            <textarea readOnly rows={5} value={plaintext} />
          </div>
        ) : null}
      </Card>
    </>
  );
}
