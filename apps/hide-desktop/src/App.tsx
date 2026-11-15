import { useEffect, useState } from "react";

import { buildInfo } from "./core";
import type { BuildInfo } from "./core";
import { Keys } from "./panels/Keys";
import { Files } from "./panels/Files";
import { Messages } from "./panels/Messages";
import { Inspect } from "./panels/Inspect";

const TABS = [
  { id: "keys", label: "Keys" },
  { id: "files", label: "Files" },
  { id: "messages", label: "Messages" },
  { id: "inspect", label: "Inspect" },
] as const;

type TabId = (typeof TABS)[number]["id"];

/**
 * There is no code-signing certificate behind these builds, so every platform
 * will warn about them. Saying so here, with the version and the way to check a
 * download, is more useful than a warning nobody can act on.
 */
function BuildNotice() {
  const [info, setInfo] = useState<BuildInfo | null>(null);

  useEffect(() => {
    void buildInfo()
      .then(setInfo)
      .catch(() => setInfo(null));
  }, []);

  if (!info) return null;

  return (
    <footer className="build" role="contentinfo">
      <p>
        HIDE {info.version}
        {info.portable ? " (portable)" : ""}. This build is <strong>unsigned</strong>
        : Windows SmartScreen or macOS Gatekeeper will warn you when you install
        or run it, and there is no certificate behind it that could stop that
        warning.
      </p>
      <p>
        The release page carries SHA-256 checksums and a Sigstore attestation.
        Check a download before you run it:{" "}
        <code>gh attestation verify &lt;file&gt; --repo hide-protocol/hide</code>
      </p>
      {info.portable ? (
        <p>
          Portable build: keys are kept in a <code>hide-keys</code> folder beside
          the program. The webview's own cache and profile still live under your
          user profile; only the keys travel with the program.
        </p>
      ) : null}
    </footer>
  );
}

export function App() {
  const [tab, setTab] = useState<TabId>("keys");

  return (
    <div className="app">
      <header className="banner" role="note">
        <strong>Experimental.</strong> HIDE has not been independently audited
        and does not verify who sent a message. Do not use it to protect data
        you cannot afford to lose or expose.
      </header>

      <nav className="tabs" aria-label="Sections">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            className={entry.id === tab ? "tab tab-active" : "tab"}
            aria-current={entry.id === tab ? "page" : undefined}
            onClick={() => setTab(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {tab === "keys" ? <Keys /> : null}
        {tab === "files" ? <Files /> : null}
        {tab === "messages" ? <Messages /> : null}
        {tab === "inspect" ? <Inspect /> : null}
      </main>

      <BuildNotice />
    </div>
  );
}
