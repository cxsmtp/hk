"use client";

import { useEffect } from "react";

import { chooseLayout, labelTable } from "@/lib/responsive-tables";

/**
 * Every table in the console becomes a list of cards where it would not fit (globals.css, table[data-cards="stack"];
 * always on a phone): one card a row, each cell under its column's name. This gives each body cell that name
 * (data-label, from the header row; a cell that already has one keeps it) and chooses cards or table whenever a table
 * appears or changes, the window is resized or the page's column changes width (the side menu folded). A table that
 * must stay a grid (a permission matrix) says so with data-table="scroll" and keeps its own scroll box instead.
 */
export function ResponsiveTables() {
  useEffect(() => {
    let frame = 0;
    const run = () => {
      frame = 0;
      const width = window.innerWidth;
      for (const table of Array.from(document.querySelectorAll("table"))) {
        labelTable(table);
        chooseLayout(table, width);
      }
    };
    const schedule = () => {
      if (!frame) frame = window.requestAnimationFrame(run);
    };
    run();
    const observer = new MutationObserver(schedule);
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener("resize", schedule);
    // A table in a <details> that opens appears without any change to the page's elements.
    document.addEventListener("toggle", schedule, true);
    const resized = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(schedule);
    const main = document.querySelector("main");
    if (resized && main) resized.observe(main);
    return () => {
      observer.disconnect();
      resized?.disconnect();
      window.removeEventListener("resize", schedule);
      document.removeEventListener("toggle", schedule, true);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, []);
  return null;
}
