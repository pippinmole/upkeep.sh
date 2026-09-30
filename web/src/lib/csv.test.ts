/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { csvCell, csvRow, toCsv } from "./csv";

describe("csvCell", () => {
  test("plain values pass through", () => {
    expect(csvCell("openssl")).toBe("openssl");
    expect(csvCell("3.0.13-0ubuntu3.4")).toBe("3.0.13-0ubuntu3.4");
    expect(csvCell(7.5)).toBe("7.5");
    expect(csvCell(0)).toBe("0");
    expect(csvCell(true)).toBe("true");
    expect(csvCell(false)).toBe("false");
  });

  test("null, undefined and non-finite numbers are empty", () => {
    expect(csvCell(null)).toBe("");
    expect(csvCell(undefined)).toBe("");
    expect(csvCell(Number.NaN)).toBe("");
    expect(csvCell(Number.POSITIVE_INFINITY)).toBe("");
    expect(csvCell("")).toBe("");
  });

  test("quotes fields with commas, quotes and line breaks (RFC 4180)", () => {
    expect(csvCell("libssl3, openssl")).toBe('"libssl3, openssl"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("line1\nline2")).toBe('"line1\nline2"');
    expect(csvCell("line1\r\nline2")).toBe('"line1\r\nline2"');
    expect(csvCell('"')).toBe('""""');
  });

  test("keeps UTF-8 text intact", () => {
    expect(csvCell("naïve café — 漢字")).toBe("naïve café — 漢字");
  });

  test.each([
    ['=HYPERLINK("http://x")', '"\'=HYPERLINK(""http://x"")"'],
    ["=1+1", "'=1+1"],
    ["+cmd", "'+cmd"],
    ["-2+3", "'-2+3"],
    ["@SUM(A1)", "'@SUM(A1)"],
    ["\tlead-tab", "'\tlead-tab"],
    ["\rlead-cr", '"\'\rlead-cr"'],
  ])("neutralises formula injection in %j", (input, expected) => {
    expect(csvCell(input)).toBe(expected);
  });

  test("only a leading trigger character is neutralised", () => {
    expect(csvCell("a=b")).toBe("a=b");
    expect(csvCell("1.2-3")).toBe("1.2-3");
    expect(csvCell("user@host")).toBe("user@host");
  });

  test("injection guard and quoting combine", () => {
    expect(csvCell("=A1,B1")).toBe('"\'=A1,B1"');
    expect(csvCell('@"x"')).toBe('"\'@""x"""');
  });

  test("numbers are never prefixed", () => {
    expect(csvCell(-1)).toBe("-1");
  });
});

describe("csvRow / toCsv", () => {
  test("joins cells with commas and ends each record with CRLF", () => {
    expect(csvRow(["a", null, 1, "b,c"])).toBe('a,,1,"b,c"\r\n');
  });

  test("writes the header first, then one record per row", () => {
    const out = toCsv(
      ["ID", "Package"],
      [
        ["CVE-2024-0001", "openssl"],
        ["CVE-2024-0002", "=evil()"],
      ],
    );
    expect(out).toBe("ID,Package\r\nCVE-2024-0001,openssl\r\nCVE-2024-0002,'=evil()\r\n");
  });

  test("a header with no rows is just the header", () => {
    expect(toCsv(["A", "B"], [])).toBe("A,B\r\n");
  });
});
