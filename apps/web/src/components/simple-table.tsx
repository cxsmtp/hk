import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export function SimpleTable({
  columns,
  rows,
  initialVisibleRows = 10,
  emptyLabel = "No data",
}: {
  columns: string[];
  rows: Array<Array<React.ReactNode>>;
  initialVisibleRows?: number;
  emptyLabel?: string;
}) {
  const threshold = Math.max(1, initialVisibleRows);
  const hasOverflow = rows.length > threshold;
  const visibleRows = hasOverflow ? rows.slice(0, threshold) : rows;
  const overflowRows = hasOverflow ? rows.slice(threshold) : [];

  function renderTableBody(tableRows: Array<Array<React.ReactNode>>) {
    if (!tableRows.length) {
      return (
        <TableRow>
          <TableCell colSpan={columns.length} className="text-center text-slate-500">
            {emptyLabel}
          </TableCell>
        </TableRow>
      );
    }
    return tableRows.map((row, idx) => (
      <TableRow key={idx}>
        {row.map((cell, j) => (
          <TableCell key={`${idx}-${j}`} className="min-w-[8.5rem] max-w-[24rem] align-top whitespace-normal break-words">
            {cell ?? "-"}
          </TableCell>
        ))}
      </TableRow>
    ));
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto overflow-y-hidden rounded-lg border border-[#2a3348]">
        <Table className="w-max min-w-full table-auto">
          <TableHeader>
            <TableRow>
              {columns.map((c) => (
                <TableHead key={c} className="whitespace-nowrap">
                  {c}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>{renderTableBody(visibleRows)}</TableBody>
        </Table>
      </div>

      {hasOverflow ? (
        <details className="rounded-lg border border-[#2a3348] bg-[#0f1218]">
          <summary className="cursor-pointer list-none px-3 py-2 text-sm text-slate-300 marker:content-none">
            Show {overflowRows.length} more rows
          </summary>
          <div className="border-t border-[#2a3348] p-3">
            <div className="overflow-x-auto overflow-y-hidden rounded-lg border border-[#2a3348]">
              <Table className="w-max min-w-full table-auto">
                <TableHeader>
                  <TableRow>
                    {columns.map((c) => (
                      <TableHead key={`more-${c}`} className="whitespace-nowrap">
                        {c}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>{renderTableBody(overflowRows)}</TableBody>
              </Table>
            </div>
            <p className="mt-2 text-xs text-slate-500">Collapse this section to return to the first {threshold} rows.</p>
          </div>
        </details>
      ) : null}
    </div>
  );
}
