export interface CsvColumn {
  key: string;
  header: string;
  /**
   * Force spreadsheet applications to import this column as text.
   *
   * Excel and Numbers coerce long digit strings into scientific notation under
   * the General format, so a 12-digit AWS account ID renders as "3.96045E+11".
   * That is cosmetic on its own, but re-saving the file from Excel writes the
   * displayed notation back to disk, which corrupts the value for any consumer
   * that reads the account ID back (for example the entitlement mapping CSV fed
   * into `--entitlement-csv`).
   *
   * Prefixing the value with a tab forces a text import. Readers in this
   * codebase trim surrounding whitespace, so the marker is transparent on a
   * round-trip. A tab is used rather than an `="..."` formula wrapper to avoid
   * introducing a CSV formula-injection vector.
   */
  text?: boolean;
}

/**
 * Parse a single CSV line respecting RFC 4180 quoted fields.
 *
 * Handles commas inside double-quoted fields and escaped double-quotes ("").
 * Returns an array of field values with surrounding quotes and whitespace trimmed.
 */
export function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let i = 0;
  while (i <= line.length) {
    if (i === line.length) { fields.push(""); break; }
    // Skip leading whitespace
    while (i < line.length && line[i] === " ") i++;
    if (i < line.length && line[i] === '"') {
      // Quoted field
      i++; // skip opening quote
      let value = "";
      while (i < line.length) {
        if (line[i] === '"') {
          if (i + 1 < line.length && line[i + 1] === '"') {
            // Escaped quote
            value += '"';
            i += 2;
          } else {
            // End of quoted field
            i++; // skip closing quote
            break;
          }
        } else {
          value += line[i];
          i++;
        }
      }
      fields.push(value.trim());
      // Skip to comma or end
      while (i < line.length && line[i] !== ",") i++;
      i++; // skip comma
    } else {
      // Unquoted field
      const start = i;
      while (i < line.length && line[i] !== ",") i++;
      fields.push(line.slice(start, i).trim());
      i++; // skip comma
    }
  }
  return fields;
}

/**
 * Export an array of objects to a CSV file and trigger a browser download.
 *
 * @param filename - Name for the downloaded file (should end with .csv).
 * @param rows - Array of flat objects. Keys of the first row define columns.
 * @param columns - Optional explicit column order, header labels, and text flags.
 */
export function exportToCsv(
  filename: string,
  rows: Record<string, unknown>[],
  columns?: CsvColumn[]
) {
  if (rows.length === 0) return;

  const cols: CsvColumn[] =
    columns ?? Object.keys(rows[0]).map((k) => ({ key: k, header: k }));

  const escape = (val: unknown, forceText = false): string => {
    const raw = val == null ? "" : String(val);
    // A leading tab tells Excel/Numbers to import the field verbatim rather
    // than guessing a numeric type. Skip empty values so blank cells stay blank.
    const str = forceText && raw !== "" ? `\t${raw}` : raw;
    // RFC 4180: if the field contains a comma, newline, tab, or double-quote,
    // wrap in double-quotes and escape embedded quotes.
    if (/[",\n\r\t]/.test(str)) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const header = cols.map((c) => escape(c.header)).join(",");
  const body = rows
    .map((row) => cols.map((c) => escape(row[c.key], c.text)).join(","))
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
