/**
 * Export an array of objects to a CSV file and trigger a browser download.
 *
 * @param filename - Name for the downloaded file (should end with .csv).
 * @param rows - Array of flat objects. Keys of the first row define columns.
 * @param columns - Optional explicit column order and header labels.
 */
export function exportToCsv(
  filename: string,
  rows: Record<string, unknown>[],
  columns?: { key: string; header: string }[]
) {
  if (rows.length === 0) return;

  const cols = columns ?? Object.keys(rows[0]).map((k) => ({ key: k, header: k }));

  const escape = (val: unknown): string => {
    const str = val == null ? "" : String(val);
    // RFC 4180: if the field contains a comma, newline, or double-quote, wrap
    // in double-quotes and escape embedded quotes.
    if (/[",\n\r]/.test(str)) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const header = cols.map((c) => escape(c.header)).join(",");
  const body = rows
    .map((row) => cols.map((c) => escape(row[c.key])).join(","))
    .join("\n");
  const csv = `${header}\n${body}`;

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
