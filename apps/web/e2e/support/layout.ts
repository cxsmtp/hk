import type { Page } from "@playwright/test";

/**
 * How a page sits in the window, for the responsive checks (e2e/responsive.spec.ts): whether the page itself scrolls
 * sideways, which elements run past the window's edges (or are cut off by the console's frame), and which boxes
 * scroll sideways inside the page (a table kept as a table, a code block): those are allowed, the rest are not.
 */

export type Offender = { selector: string; left: number; right: number; text: string };
/** intended: a grid that must stay a grid (table[data-table=scroll]) or preformatted text (pre). */
export type SideScroller = { selector: string; scrollWidth: number; clientWidth: number; intended: boolean };
export type LayoutReport = {
  viewport: number;
  /** How far the page itself scrolls sideways (0: it does not). */
  pageOverflow: number;
  /** Elements past the window's left or right edge, outside any box that scrolls sideways on purpose. */
  offenders: Offender[];
  /** Boxes that scroll sideways inside the page. */
  sideScrollers: SideScroller[];
};

export async function measureLayout(page: Page): Promise<LayoutReport> {
  return page.evaluate(() => {
    const viewport = document.documentElement.clientWidth;
    const scroller = document.scrollingElement || document.documentElement;
    const pageOverflow = Math.max(0, scroller.scrollWidth - scroller.clientWidth, document.body.scrollWidth - viewport);

    const describe = (el: Element): string => {
      const parts: string[] = [];
      let node: Element | null = el;
      for (let depth = 0; node && depth < 3 && node !== document.body; depth += 1) {
        let part = node.tagName.toLowerCase();
        if (node.id) part += `#${node.id}`;
        const cls = typeof node.className === "string" ? node.className.trim().split(/\s+/).filter(Boolean).slice(0, 3) : [];
        if (cls.length) part += `.${cls.join(".")}`;
        const ui = node.getAttribute("data-ui");
        if (ui) part += `[data-ui=${ui}]`;
        parts.unshift(part);
        node = node.parentElement;
      }
      return parts.join(" > ");
    };

    const shown = (el: Element): boolean => {
      // Inside a closed <details> (other than its summary): not on the screen, whatever its box says.
      const closed = el.closest("details:not([open])");
      if (closed && closed !== el && !el.closest("summary")) return false;
      const style = getComputedStyle(el);
      if (style.visibility === "hidden" || style.display === "none" || Number(style.opacity) === 0) return false;
      const r = el.getBoundingClientRect();
      return r.width > 1 && r.height > 1;
    };

    // What a box does with content wider than itself: "scroll" (on purpose), "clip" (cut off), or "visible".
    const overflowX = (el: Element): "scroll" | "clip" | "visible" => {
      const value = getComputedStyle(el).overflowX;
      if (value === "auto" || value === "scroll") return "scroll";
      if (value === "hidden" || value === "clip") return "clip";
      return "visible";
    };

    const offenders: Offender[] = [];
    const flagged = new Set<Element>();
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      if (el.closest("svg") && el.tagName.toLowerCase() !== "svg") continue;
      const r = el.getBoundingClientRect();
      if (r.right <= viewport + 1 && r.left >= -1) continue;
      if (!shown(el)) continue;
      if (getComputedStyle(el).position === "fixed" && (r.right <= 0 || r.left >= viewport)) continue;
      let allowed = false;
      for (let a = el.parentElement; a && a !== document.documentElement; a = a.parentElement) {
        const mode = overflowX(a);
        if (mode === "scroll") {
          allowed = true;
          break;
        }
        if (mode === "clip") {
          // Cut off by a box that is itself inside the window (a truncated label, a chart, a marquee): fine. Cut off
          // by the console's frame (main, body): content the reader cannot reach.
          const ar = a.getBoundingClientRect();
          const frame = a === document.body || a.tagName === "MAIN";
          if (!frame && ar.right <= viewport + 1 && ar.left >= -1) allowed = true;
          break;
        }
      }
      if (allowed) continue;
      flagged.add(el);
      if (el.parentElement && flagged.has(el.parentElement)) continue;
      offenders.push({
        selector: describe(el),
        left: Math.round(r.left),
        right: Math.round(r.right),
        text: (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 60),
      });
    }

    // The page scrolls sideways but nothing visible is past the edge: name what is (an invisible tooltip, a menu
    // kept off the screen), so the cause can be found.
    if (pageOverflow > 0 && !offenders.length) {
      // Absolutely placed boxes first: they escape a scroll box that is not itself positioned.
      const beyond = Array.from(document.body.querySelectorAll("*")).filter((el) => el.getBoundingClientRect().right > viewport + 1);
      const placed = beyond.filter((el) => ["absolute", "fixed"].includes(getComputedStyle(el).position));
      for (const el of [...placed, ...beyond.filter((el) => !placed.includes(el))]) {
        const r = el.getBoundingClientRect();
        offenders.push({ selector: `(past the edge) ${describe(el)}`, left: Math.round(r.left), right: Math.round(r.right), text: (el.textContent || "").trim().slice(0, 60) });
        if (offenders.length >= 5) break;
      }
    }

    const sideScrollers: SideScroller[] = [];
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      if (overflowX(el) !== "scroll") continue;
      if (el.scrollWidth <= el.clientWidth + 1 || !shown(el)) continue;
      const intended = el.tagName === "PRE" || Boolean(el.querySelector("table[data-table=scroll], pre"));
      sideScrollers.push({ selector: describe(el), scrollWidth: el.scrollWidth, clientWidth: el.clientWidth, intended });
    }

    return { viewport, pageOverflow, offenders: offenders.slice(0, 20), sideScrollers: sideScrollers.slice(0, 20) };
  });
}
