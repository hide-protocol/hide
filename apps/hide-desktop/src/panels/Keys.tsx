import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import {
  defaultKeyDirectory,
  generateKeys,
  messageOf,
  readPublicArmor,
} from "../core";
import type { KeyPair } from "../core";
import { Card, Field, PathPicker, StatusLine } from "../ui";
import type { Status } from "../ui";

const MIN_PASSPHRASE = 8;

export function Keys() {
  const [directory, setDirectory] = useState<string | null>(null);
  const [name, setName] = useState("my-key");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [unprotected, setUnprotected] = useState(false);
  const [created, setCreated] = useState<KeyPair | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const [shared, setShared] = useState<string | null>(null);
  const [shareStatus, setShareStatus] = useState<Status>({ kind: "idle" });

  // A portable build offers its own folder, so keys travel with the program.
  useEffect(() => {
    void defaultKeyDirectory()
      .then((path) => {
        if (path) setDirectory((current) => current ?? path);
      })
      .catch(() => {
        /* Not portable; the user picks a folder. */
      });
  }, []);

  async function pickDirectory() {
    const chosen = await open({ directory: true, multiple: false });
    if (typeof chosen === "string") setDirectory(chosen);
  }

  async function create() {
    if (!directory) {
      setStatus({ kind: "error", text: "Choose where to save the key." });
      return;
    }
    if (!unprotected) {
      if (passphrase.length < MIN_PASSPHRASE) {
        setStatus({
          kind: "error",
          text: `The passphrase must be at least ${MIN_PASSPHRASE} characters.`,
        });
        return;
      }
      if (passphrase !== confirmation) {
        setStatus({ kind: "error", text: "The passphrases do not match." });
        return;
      }
    }

    setStatus({ kind: "busy", text: "Generating a key pair." });
    try {
      const pair = await generateKeys(
        directory,
        name,
        unprotected ? null : passphrase,
      );
      setCreated(pair);
      setPassphrase("");
      setConfirmation("");
      setStatus({
        kind: "ok",
        text: pair.protected
          ? "Key created and sealed with your passphrase. If you forget it, nothing encrypted to this key can be recovered."
          : "Key created WITHOUT a passphrase. Anyone who copies the file can decrypt your data.",
      });
    } catch (error) {
      setStatus({ kind: "error", text: messageOf(error) });
    }
  }

  async function share() {
    const chosen = await open({
      multiple: false,
      filters: [{ name: "HIDE public key", extensions: ["hide-pub"] }],
    });
    if (typeof chosen !== "string") return;
    try {
      setShared(await readPublicArmor(chosen));
      setShareStatus({ kind: "idle" });
    } catch (error) {
      setShared(null);
      setShareStatus({ kind: "error", text: messageOf(error) });
    }
  }

  return (
    <>
      <Card
        title="Create a key"
        description="Your secret key decrypts everything sent to you; the public key is what you hand out."
      >
        <PathPicker
          label="Save in"
          value={directory}
          buttonText="Choose folder"
          onPick={pickDirectory}
        />
        <Field label="Name" hint="Used for the two filenames.">
          <input value={name} onChange={(event) => setName(event.target.value)} />
        </Field>

        {unprotected ? null : (
          <>
            <Field
              label="Passphrase"
              hint={`At least ${MIN_PASSPHRASE} characters. It cannot be reset or recovered.`}
            >
              <input
                type="password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
              />
            </Field>
            <Field label="Confirm passphrase">
              <input
                type="password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </Field>
          </>
        )}

        <label className="checkbox">
          <input
            type="checkbox"
            checked={unprotected}
            onChange={(event) => setUnprotected(event.target.checked)}
          />
          <span>
            Skip the passphrase — for disposable test keys only. The secret is
            written to disk unencrypted.
          </span>
        </label>

        <button type="button" className="primary" onClick={create}>
          Create key
        </button>
        <StatusLine status={status} />

        {created ? (
          <div className="result">
            <p>
              Secret key: <code>{created.secret_path}</code>
            </p>
            <p>
              Public key: <code>{created.public_path}</code>
            </p>
            <p className="field-label">Public key, for pasting:</p>
            <textarea readOnly rows={4} value={created.armored_public} />
          </div>
        ) : null}
      </Card>

      <Card
        title="Share a public key"
        description="Send this to anyone who wants to encrypt something for you. It is not secret."
      >
        <button type="button" onClick={share}>
          Choose a public key
        </button>
        <StatusLine status={shareStatus} />
        {shared ? (
          <>
            <textarea readOnly rows={4} value={shared} />
            <p className="field-hint">
              Send it over a channel where the other person can confirm it really
              came from you. HIDE cannot check that for you.
            </p>
          </>
        ) : null}
      </Card>
    </>
  );
}
