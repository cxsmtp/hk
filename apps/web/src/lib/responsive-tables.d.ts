/** Types for responsive-tables.mjs (tables as cards on a narrow screen). */
export function columnNames(table: HTMLTableElement): { names: string[]; row: HTMLTableRowElement | null };
export function labelTable(table: HTMLTableElement): void;
export const PHONE_WIDTH: number;
export function chooseLayout(table: HTMLTableElement, viewportWidth: number): void;
