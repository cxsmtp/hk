/**
 * Tables as cards on a narrow screen (components/responsive-tables.tsx, globals.css table[data-cards]): each body cell
 * is given its column's name as data-label, taken from the header row (colspan counted), unless it has one already.
 * A table marked data-table="scroll" stays a grid, and one with a phone layout of its own (data-table="own", the
 * guide's .guide-table) is left alone too. Works on anything shaped like the DOM's tables.
 */

const text = (cell) => (cell.textContent || "").replace(/\s+/g, " ").trim();

/** The column names of a table, one per column (a header cell spanning two columns names both). */
export function columnNames(table) {
  const head = table.tHead && table.tHead.rows.length ? table.tHead.rows[table.tHead.rows.length - 1] : null;
  const first = !head && table.rows.length ? table.rows[0] : null;
  const row = head || (first && first.cells.length > 1 && Array.from(first.cells).every((cell) => cell.tagName === "TH") ? first : null);
  if (!row) return { names: [], row: null };
  const names = [];
  for (const cell of Array.from(row.cells)) {
    const span = Math.max(1, Number(cell.colSpan) || 1);
    for (let i = 0; i < span; i += 1) names.push(text(cell));
  }
  return { names, row };
}

export function labelTable(table) {
  if (table.hasAttribute("data-table") || /(^| )guide-table( |$)/.test(table.getAttribute("class") || "")) {
    if (table.hasAttribute("data-cards")) table.removeAttribute("data-cards");
    return;
  }
  if (!table.hasAttribute("data-cards")) table.setAttribute("data-cards", "table");
  const { names, row: headerRow } = columnNames(table);
  if (headerRow && !table.tHead) headerRow.setAttribute("data-card-head", "");
  if (!names.length) return;
  for (const row of Array.from(table.rows)) {
    if (row === headerRow || (table.tHead && row.parentElement === table.tHead)) continue;
    let column = 0;
    for (const cell of Array.from(row.cells)) {
      const name = names[column] || "";
      if (name && !cell.hasAttribute("data-label")) cell.setAttribute("data-label", name);
      column += Math.max(1, Number(cell.colSpan) || 1);
    }
  }
}

/** Below this width (a phone) every table is a list of cards. */
export const PHONE_WIDTH = 768;

/**
 * Cards or a table: a table stays a table only where it fits the box it is in (with a phone's width, never), so no
 * table ever needs a sideways scroll. Measured as a table each time (in the same frame, so nothing flickers):
 * "stack" when it is wider than the box around it.
 */
export function chooseLayout(table, viewportWidth) {
  if (!table.hasAttribute("data-cards")) return;
  if (viewportWidth < PHONE_WIDTH) {
    if (table.getAttribute("data-cards") !== "stack") table.setAttribute("data-cards", "stack");
    return;
  }
  const box = table.parentElement;
  if (!box) return;
  if (table.getAttribute("data-cards") !== "table") table.setAttribute("data-cards", "table");
  const fits = table.offsetWidth <= box.clientWidth + 1;
  if (!fits) table.setAttribute("data-cards", "stack");
}
