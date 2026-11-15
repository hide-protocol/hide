import { useState } from "react";

import { chooseFile, describe, messageOf } from "../core";
import type { Description } from "../core";
import { Card, StatusLine } from "../ui";
import type { Status } from "../ui";

export function Inspect() {
  const [result, setResult] = useState<Description | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  async function choose() {
    const chosen = await chooseFile("any");
    if (!chosen) return;
    try {
      setResult(await describe(chosen.id));
      setStatus({ kind: "idle" });
    } catch (error) {
      setResult(null);
      setStatus({ kind: "error", text: messageOf(error) });
    }
  }

  return (
    <Card
      title="Identify a file"
      description="Tells you what a file is without decrypting it or asking for a passphrase."
    >
      <button type="button" onClick={choose}>
        Choose a file
      </button>
      <StatusLine status={status} />
      {result ? (
        <div className="result">
          <h3>{result.kind}</h3>
          <p>{result.detail}</p>
          {result.warning ? (
            <p className="status status-error" role="alert">
              {result.warning}
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
