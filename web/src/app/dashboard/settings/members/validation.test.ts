import { describe, expect, test } from "bun:test";

import { generateTemporaryPassword, validateNewMember, validatePassword } from "./validation";

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
