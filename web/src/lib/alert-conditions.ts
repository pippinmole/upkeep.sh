// Alert rule conditions (docs/ALERTING.md). The property catalogue is
// declared in Go (server/internal/alerting/catalog.go) and generated into
// alert-properties.json (`go test ./internal/alerting -update`, checked by
// a golden test), so the rule dialog renders and validates from the same
// declaration the worker evaluates. validateCondition mirrors
// alerting.Validate; alert-conditions.vectors.json is run against both.
// Adding a property needs no change here.
import catalog from "./alert-properties.json";

export type ValueKind = "none" | "int_list" | "string_list" | "enum" | "int";
export type Choice = { value: string; label: string };

export type ValueSpec = {
  kind: ValueKind;
  label?: string;
  placeholder?: string;
  help?: string;
  min?: number;
  max?: number;
  maxItems?: number;
  maxLength?: number;
  pattern?: string;
  lower?: boolean;
  choices?: Choice[];
  unit?: string;
};

export type Operator = { key: string; label: string; value: ValueSpec };
export type OptionSpec = {
  key: string;
  label: string;
  help?: string;
  default: string;
  choices: Choice[];
};
export type Property = {
  key: string;
  label: string;
  description: string;
  subject?: string;
  operators: Operator[];
  options?: OptionSpec[];
};

export const PROPERTIES = catalog.properties as Property[];

export function propertyByKey(key: string): Property | undefined {
  return PROPERTIES.find((p) => p.key === key);
}

export type ConditionValue = number[] | string[] | string | number;

export type Condition = {
  property: string;
  operator: string;
  value?: ConditionValue;
  options?: Record<string, string>;
};

export type ConditionResult =
  | { ok: true; condition: Condition }
  | { ok: false; field: string; message: string };

const fail = (field: string, message: string): ConditionResult => ({ ok: false, field, message });

type ValueResult = { ok: true; value?: ConditionValue } | { ok: false; message: string };

function normalizeValue(spec: ValueSpec, raw: unknown): ValueResult {
  const isNull = raw === undefined || raw === null;
  switch (spec.kind) {
    case "none":
      return isNull ? { ok: true } : { ok: false, message: "this operator takes no value" };
    case "int_list": {
      if (!Array.isArray(raw) || !raw.every((n) => typeof n === "number")) {
        return { ok: false, message: "enter a list of numbers" };
      }
      const out: number[] = [];
      for (const n of raw as number[]) {
        if (!Number.isInteger(n) || n < (spec.min ?? 0) || n > (spec.max ?? 0)) {
          return {
            ok: false,
            message: `${n} is not a whole number from ${spec.min} to ${spec.max}`,
          };
        }
        if (!out.includes(n)) out.push(n);
      }
      if (out.length === 0) return { ok: false, message: "enter at least one" };
      if (spec.maxItems && out.length > spec.maxItems) {
        return { ok: false, message: `at most ${spec.maxItems}` };
      }
      return { ok: true, value: out.sort((a, b) => a - b) };
    }
    case "string_list": {
      if (!Array.isArray(raw) || !raw.every((s) => typeof s === "string")) {
        return { ok: false, message: "enter a list of names" };
      }
      const re = spec.pattern ? new RegExp(spec.pattern) : null;
      const out: string[] = [];
      for (let s of raw as string[]) {
        s = s.trim();
        if (spec.lower) s = s.toLowerCase();
        if (s === "" || out.includes(s)) continue;
        if (spec.maxLength && [...s].length > spec.maxLength) {
          return { ok: false, message: `"${s}" is longer than ${spec.maxLength} characters` };
        }
        if (re && !re.test(s)) return { ok: false, message: `"${s}" is not a valid name` };
        out.push(s);
      }
      if (out.length === 0) return { ok: false, message: "enter at least one" };
      if (spec.maxItems && out.length > spec.maxItems) {
        return { ok: false, message: `at most ${spec.maxItems}` };
      }
      // Byte order, like Go's sort.Strings.
      return { ok: true, value: out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)) };
    }
    case "enum":
      if (typeof raw !== "string" || !spec.choices?.some((c) => c.value === raw)) {
        return { ok: false, message: "choose one of the listed values" };
      }
      return { ok: true, value: raw };
    case "int":
      if (
        typeof raw !== "number" ||
        !Number.isInteger(raw) ||
        raw < (spec.min ?? 0) ||
        raw > (spec.max ?? 0)
      ) {
        return { ok: false, message: `enter a whole number from ${spec.min} to ${spec.max}` };
      }
      return { ok: true, value: raw };
  }
  return { ok: false, message: "unsupported value" };
}

// Validates and normalises a condition exactly like the Go side: lists
// de-duplicated and sorted (strings trimmed, lower-cased where declared),
// option defaults filled in, a "none" value dropped.
export function validateCondition(input: unknown): ConditionResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return fail("property", "invalid condition");
  }
  const c = input as Record<string, unknown>;
  for (const k of Object.keys(c)) {
    if (!["property", "operator", "value", "options"].includes(k)) {
      return fail("property", `unknown field ${k}`);
    }
  }
  const p = propertyByKey(String(c.property));
  if (!p) return fail("property", "Choose a property");
  const op = p.operators.find((o) => o.key === c.operator);
  if (!op) return fail("operator", "Choose an operator");
  const v = normalizeValue(op.value, c.value);
  if (!v.ok) return fail("value", v.message.charAt(0).toUpperCase() + v.message.slice(1));
  const out: Condition = { property: p.key, operator: op.key };
  if (v.value !== undefined) out.value = v.value;

  const given = (c.options ?? {}) as Record<string, unknown>;
  if (typeof given !== "object" || Array.isArray(given)) return fail("options", "invalid options");
  for (const k of Object.keys(given)) {
    if (!p.options?.some((o) => o.key === k)) return fail(`options.${k}`, `No option ${k}`);
  }
  if (p.options?.length) {
    out.options = {};
    for (const o of p.options) {
      let val = given[o.key];
      if (val === undefined || val === null || val === "") val = o.default;
      if (typeof val !== "string" || !o.choices.some((ch) => ch.value === val)) {
        return fail(`options.${o.key}`, `Invalid ${o.label.toLowerCase()}`);
      }
      out.options[o.key] = val;
    }
  }
  return { ok: true, condition: out };
}

function choiceLabel(choices: Choice[] | undefined, value: string): string {
  return choices?.find((c) => c.value === value)?.label ?? value;
}

function listText(values: (string | number)[]): string {
  if (values.length <= 3) return values.join(", ");
  return `${values.slice(0, 3).join(", ")} +${values.length - 3} more`;
}

export function minutesText(m: number): string {
  if (m % 1440 === 0) return m === 1440 ? "1 day" : `${m / 1440} days`;
  if (m % 60 === 0) return m === 60 ? "1 hour" : `${m / 60} hours`;
  return m === 1 ? "1 minute" : `${m} minutes`;
}

// A condition in words, e.g. "Listening port is one of 22 (TCP, any
// address except loopback)".
export function describeCondition(c: Condition): string {
  const p = propertyByKey(c.property);
  if (!p) return `${c.property} ${c.operator}`;
  const op = p.operators.find((o) => o.key === c.operator);
  let s = `${p.label} ${op?.label ?? c.operator}`;
  const v = c.value;
  if (Array.isArray(v)) s += ` ${listText(v)}`;
  else if (op?.value.kind === "enum" && typeof v === "string")
    s += ` ${choiceLabel(op.value.choices, v).toLowerCase()}`;
  else if (op?.value.unit === "minutes" && typeof v === "number") s += ` ${minutesText(v)}`;
  else if (v !== undefined) s += ` ${v}`;
  const opts = (p.options ?? [])
    .filter((o) => c.options?.[o.key] && c.options[o.key] !== o.default)
    .map((o) => choiceLabel(o.choices, c.options![o.key]));
  if (p.key === "listening_port") {
    // Always say which addresses count: it's what the rule is about.
    const bind = p.options?.find((o) => o.key === "bind");
    const proto = p.options?.find((o) => o.key === "protocol");
    const parts = [
      choiceLabel(proto?.choices, c.options?.protocol ?? "tcp"),
      choiceLabel(bind?.choices, c.options?.bind ?? "non_loopback").toLowerCase(),
    ];
    return `${s} (${parts.join(", ")})`;
  }
  return opts.length ? `${s} (${opts.join(", ").toLowerCase()})` : s;
}
