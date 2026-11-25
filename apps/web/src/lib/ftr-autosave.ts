/**
 * FTR Command Center's settings forms (ftr-cc-dashboard public/js/settings.js `autosave`), for Hawk's Settings pages:
 * a form that saves as it is typed in. `save(form)` is called after a pause (text) or at once (a choice), and when it
 * fails the form shows the last good values again. The status is written into `status` (a `.saved-foot`).
 *
 * Used on uncontrolled forms (inputs with defaultValue / defaultChecked), as FTR's are plain HTML forms.
 */

export const SAVES_AS_YOU_TYPE = "✓ Changes save as you type.";

type Field = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;

function fieldsOf(form: HTMLFormElement, keep: string[]): Field[] {
  return [...form.elements].filter(
    (el): el is Field =>
      (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) &&
      Boolean(el.name) &&
      !keep.includes(el.name) &&
      el.type !== "password" &&
      el.type !== "file",
  );
}

export function autosave(
  form: HTMLFormElement,
  save: (form: HTMLFormElement) => Promise<string | void>,
  { status, delay = 700, keep = [] }: { status?: HTMLElement | null; delay?: number; keep?: string[] } = {},
): { run: () => Promise<void>; stop: () => void } {
  const snap = () =>
    Object.fromEntries(fieldsOf(form, keep).map((el) => [el.name, el instanceof HTMLInputElement && el.type === "checkbox" ? el.checked : el.value])) as Record<string, string | boolean>;
  let good = snap();
  let timer: ReturnType<typeof setTimeout> | null = null;
  const say = (text: string, cls = "") => {
    if (!status) return;
    status.textContent = text;
    status.className = `saved-foot ${cls}`.trim();
  };
  const run = async () => {
    if (timer) clearTimeout(timer);
    say("Saving…");
    // What is sent now becomes the last good setting once saved (not what is typed meanwhile).
    const sent = snap();
    try {
      const message = await save(form);
      good = sent;
      say(message || `All changes are saved ✓ ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`);
    } catch (error) {
      // The last good setting stays: on the server, and in the form.
      for (const [name, value] of Object.entries(good)) {
        const el = form.elements.namedItem(name);
        if (el instanceof HTMLInputElement && el.type === "checkbox") el.checked = Boolean(value);
        else if (el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement) el.value = String(value);
      }
      const text = error instanceof Error ? error.message : String(error);
      say(`${text}${/back\.|kept\./.test(text) ? "" : " The last good setting is kept."}`, "bad");
    }
  };
  const onSubmit = (event: Event) => {
    event.preventDefault();
    void run();
  };
  const onInput = (event: Event) => {
    const target = event.target as Field;
    if (["checkbox", "radio", "select-one", "file"].includes(target.type)) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void run(), target.tagName === "TEXTAREA" ? 1200 : delay);
  };
  const onChange = (event: Event) => {
    if ((event.target as Field).type === "file") return;
    void run();
  };
  form.addEventListener("submit", onSubmit);
  form.addEventListener("input", onInput);
  form.addEventListener("change", onChange);
  return {
    run,
    stop: () => {
      if (timer) clearTimeout(timer);
      form.removeEventListener("submit", onSubmit);
      form.removeEventListener("input", onInput);
      form.removeEventListener("change", onChange);
    },
  };
}
