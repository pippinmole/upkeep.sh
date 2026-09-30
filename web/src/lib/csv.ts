// RFC 4180 CSV serialization for dashboard exports.
//
//   - Records end in CRLF; the last one too.
//   - A field is quoted when it contains a comma, double quote, CR or LF,
//     and a double quote inside a field is doubled.
//   - Formula injection (OWASP "CSV Injection"): a string cell starting with
//     =, +, -, @, tab or CR is prefixed with a single quote, so Excel,
//     LibreOffice and Sheets show it as text instead of evaluating it.
//     Package names, versions and advisory text come from feeds and agents,
//     so none of them is trusted.
//
// Numbers and booleans are written as-is (a number can't be a formula; a
// negative one would be, but callers never export any). null/undefined is
// an empty field. The caller sends the result as UTF-8.

export type CsvCell = string | number | boolean | null | undefined;

const FORMULA_START = /^[=+\-@\t\r]/;
const NEEDS_QUOTES = /[",\r\n]/;

export function csvCell(value: CsvCell): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "";
  if (typeof value === "boolean") return value ? "true" : "false";
  const s = FORMULA_START.test(value) ? `'${value}` : value;
  return NEEDS_QUOTES.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

export function csvRow(cells: readonly CsvCell[]): string {
  return `${cells.map(csvCell).join(",")}\r\n`;
}

export function toCsv(header: readonly string[], rows: readonly (readonly CsvCell[])[]): string {
  return csvRow(header) + rows.map(csvRow).join("");
}
