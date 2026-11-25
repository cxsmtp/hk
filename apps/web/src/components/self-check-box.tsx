"use client";

import { healthChip, problemLine } from "@/lib/hands-off-settings";
import type { SelfCheckHealth } from "@/lib/hands-off-settings";

const dateTime = (iso?: string | null) => (iso ? new Date(iso).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "—");

/** The self-check box: what is wrong now, when the last check ran, the last events, and Check now (MZ's .ho-health). */
export function SelfCheckBox({ health, onCheck, busy }: { health: SelfCheckHealth | null; onCheck: () => void; busy: boolean }) {
  const chip = healthChip(health);
  return (
    <>
      <p>
        <span className={`chip ${chip.tone}`}>
          <i />
          {chip.label}
        </span>{" "}
        {chip.text}
      </p>
      {health?.problems.length ? (
        <ul className="small" id="ho-problems">
          {health.problems.map((p) => (
            <li key={p.key}>{problemLine(p)}</li>
          ))}
        </ul>
      ) : null}
      {health?.events.length ? (
        <>
          <h3>Last events</h3>
          <ul className="small" id="ho-events">
            {health.events.slice(0, 8).map((e, i) => (
              <li key={`${e.at}-${i}`}>
                {dateTime(e.at)}: {e.message}
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <p className="muted small">
        Every {health?.everyMinutes ?? 5} minutes Hawk AI checks its database, Redis, the worker and the scheduler, the email server, its Checkmarx One connections, its automatic runs and its error rate. It puts right what it can, each repair once while a problem lasts, and tells the administrators after two checks in a row.
        {health?.maintainer ? ` Support cases it raises by itself go to the administrators, to forward to ${health.maintainer}.` : ""}
      </p>
      <div className="flex">
        <button type="button" className="ghost sm" id="ho-check" disabled={busy} onClick={onCheck}>
          Check now
        </button>
      </div>
    </>
  );
}

