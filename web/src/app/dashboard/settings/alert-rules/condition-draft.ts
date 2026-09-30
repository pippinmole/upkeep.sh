import {
  type Condition,
  type ConditionValue,
  propertyByKey,
  type ValueSpec,
} from "@/lib/alert-conditions";

// The rule dialog's editable form of a condition: the value as the user
// types it ("22, 3389"), parsed into a Condition on submit and validated
// by validateCondition (the server validates again).
export type ConditionDraft = {
  property: string;
  operator: string;
  valueText: string;
  options: Record<string, string>;
};

export function valueToText(v: ConditionValue | undefined): string {
  if (v === undefined) return "";
  return Array.isArray(v) ? v.join(", ") : String(v);
}

export function draftFromCondition(c: Condition): ConditionDraft {
  return {
    property: c.property,
    operator: c.operator,
    valueText: valueToText(c.value),
    options: { ...c.options },
  };
}

// A new property starts on its first operator with default options.
export function draftForProperty(key: string): ConditionDraft {
  const p = propertyByKey(key);
  const op = p?.operators[0];
  return {
    property: key,
    operator: op?.key ?? "",
    valueText: op?.value.kind === "enum" ? (op.value.choices?.[0]?.value ?? "") : "",
    options: Object.fromEntries((p?.options ?? []).map((o) => [o.key, o.default])),
  };
}

function parseValue(spec: ValueSpec | undefined, text: string): unknown {
  const t = text.trim();
  switch (spec?.kind) {
    case "int_list":
      return t === ""
        ? []
        : t
            .split(/[\s,]+/)
            .filter(Boolean)
            .map(Number);
    case "string_list":
      // Commas only: package names can contain spaces (Windows programs).
      return t.split(",");
    case "int":
      return t === "" ? null : Number(t);
    case "enum":
      return t;
    default:
      return undefined;
  }
}

export function conditionFromDraft(d: ConditionDraft): unknown {
  const op = propertyByKey(d.property)?.operators.find((o) => o.key === d.operator);
  const value = parseValue(op?.value, d.valueText);
  return {
    property: d.property,
    operator: d.operator,
    ...(value === undefined ? {} : { value }),
    ...(Object.keys(d.options).length ? { options: d.options } : {}),
  };
}
