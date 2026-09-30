import { describe, expect, test } from "bun:test";

import {
  firstInvalidField,
  generateTemporaryPassword,
  signInDetailsText,
  validateNewMember,
  validatePassword,
} from "./validation";

const ok = {
  username: "Jane.Doe",
  email: " Jane@Example.com ",
  name: "Jane",
  role: "member",
  password: "correct horse",
};

describe("validateNewMember", () => {
  test("accepts a valid member and normalises the email", () => {
    const { member, fieldErrors } = validateNewMember(ok);
    expect(fieldErrors).toEqual({});
    expect(member).toEqual({
      username: "Jane.Doe",
      email: "jane@example.com",
      name: "Jane",
      role: "member",
      password: "correct horse",
    });
  });

  test("rejects each bad field", () => {
    const { member, fieldErrors } = validateNewMember({
      username: "a!",
      email: "nope",
      role: "owner",
      password: "short",
    });
    expect(member).toBeNull();
    expect(Object.keys(fieldErrors).sort()).toEqual(["email", "password", "role", "username"]);
  });

  test("rejects non-object input", () => {
    expect(validateNewMember(null).member).toBeNull();
  });
});

describe("validatePassword", () => {
  test("enforces 8..128 characters", () => {
    expect(validatePassword("1234567")).not.toBeNull();
    expect(validatePassword("12345678")).toBeNull();
    expect(validatePassword("x".repeat(129))).not.toBeNull();
    expect(validatePassword(undefined)).not.toBeNull();
  });
});

describe("generateTemporaryPassword", () => {
  test("is long enough, valid and varies", () => {
    const a = generateTemporaryPassword();
    expect(a).toHaveLength(16);
    expect(validatePassword(a)).toBeNull();
    expect(a).not.toMatch(/[0O1lI]/);
    expect(generateTemporaryPassword()).not.toBe(a);
  });
});

describe("firstInvalidField", () => {
  test("follows the dialog's field order, not the object's", () => {
    expect(firstInvalidField({ password: "x", email: "y" })).toBe("email");
    expect(firstInvalidField({ role: "x", username: "y" })).toBe("username");
  });

  test("is null when nothing is invalid", () => {
    expect(firstInvalidField({})).toBeNull();
  });
});

describe("signInDetailsText", () => {
  const d = { loginUrl: "https://upkeep.example/login", username: "alice", password: "Xy7kPq" };

  test("lists the page, username and temporary password", () => {
    expect(signInDetailsText(d)).toBe(
      [
        "Sign in to upkeep.sh",
        "Page: https://upkeep.example/login",
        "Username: alice",
        "Temporary password: Xy7kPq",
        "You'll choose your own password when you first sign in.",
      ].join("\n"),
    );
  });

  test("says next sign-in after a reset", () => {
    expect(signInDetailsText({ ...d, reset: true })).toEndWith("when you next sign in.");
  });
});
