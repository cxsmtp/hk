"use client";

import "../../settings/ftr-settings.css";

import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { linkToken } from "@/lib/hands-off-settings";
import { errorMessageFrom } from "@/lib/licence";

const EXPIRED = { title: "This link has expired", message: "Links in Hawk AI emails work for 30 days. The next email has fresh ones." };

/**
 * The page a button in one of Hawk AI's emails opens (CxMissionZero's /a/:token, src/routes/hands-off.js):
 * /hands-off/confirm#a=<token>. It says what the link would do and for whom, and does it only after "Yes, do it", so a
 * mail scanner that opens every link never changes anything. No sign-in: the link is signed for the person it was sent
 * to and works for 30 days. The token is after "#", so browsers never send it to a server or in a Referer, and the page
 * takes it out of the address bar at once.
 */
export default function HandsOffConfirmPage() {
  const [token, setToken] = useState("");
  const [title, setTitle] = useState("Checking the link…");
  const [text, setText] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const found = linkToken(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (!found) {
      setTitle(EXPIRED.title);
      setText(EXPIRED.message);
      return;
    }
    api
      .describeHandsOffLink(found)
      .then((answer) => {
        setToken(found);
        setTitle(answer.title);
        setText(answer.message);
        setConfirm(answer.confirm || "Yes, do it");
      })
      .catch((error) => {
        setTitle(EXPIRED.title);
        setText(errorMessageFrom(error instanceof Error ? error.message : "", EXPIRED.message));
      });
  }, []);

  async function act() {
    setBusy(true);
    try {
      const done = await api.confirmHandsOffLink(token);
      setTitle(done.title);
      setText(done.message);
    } catch (error) {
      setTitle("Not done");
      setText(errorMessageFrom(error instanceof Error ? error.message : "", "Something went wrong on the server. The details are in its log."));
    } finally {
      setToken("");
      setConfirm("");
      setBusy(false);
    }
  }

  return (
    <main className="ftr-settings" data-ui="hands-off-confirm" style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 16, background: "var(--bg)" }}>
      <div className="panel" style={{ maxWidth: 480, width: "100%" }}>
        <p className="muted small">Hawk AI</p>
        <h2>{title}</h2>
        {text ? <p>{text}</p> : null}
        {token && confirm ? (
          <div className="flex mt">
            <button type="button" className="primary" id="ho-confirm" disabled={busy} onClick={act}>
              {confirm}
            </button>
          </div>
        ) : null}
      </div>
    </main>
  );
}
