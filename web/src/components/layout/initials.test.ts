/// <reference types="bun" />

import { expect, test } from "bun:test";

import { initialsFor } from "./initials";

test("first letters of the first and last words", () => {
  expect(initialsFor({ name: "Jonathan Ruffles", email: "j@example.com" })).toBe("JR");
  expect(initialsFor({ name: "  ada  king lovelace ", email: "a@example.com" })).toBe("AL");
});

test("one word, or no name, takes the first two letters", () => {
  expect(initialsFor({ name: "jonny", email: "j@example.com" })).toBe("JO");
  expect(initialsFor({ name: "", email: "max@example.com" })).toBe("MA");
  expect(initialsFor({ name: "   ", email: "max@example.com" })).toBe("MA");
});
