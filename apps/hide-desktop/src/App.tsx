import { useState } from "react";

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
    </div>
  );
}
