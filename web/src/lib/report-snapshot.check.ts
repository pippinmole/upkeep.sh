// Type-level check only: `bunx tsc --noEmit` fails when the shared fixture
// (also round-tripped through the Go types by `go test ./internal/reports`)
// no longer matches ReportSnapshot. Not imported by the app.
//
// A JSON import widens string literals to `string`, so the fixture is
// checked against ReportSnapshot with its literal unions relaxed to string
// (Loose). Two directions: `satisfies Loose<ReportSnapshot>` fails on a
// field the type has and the fixture lacks (or has with another type);
// Exact fails on a field the fixture has and the type lacks (satisfies does
// no excess-property check on an imported value).

import example from "./report-snapshot.example.json";
import type { ReportSnapshot } from "./report-snapshot";

// Replace string literal unions with string, recursively.
type Loose<T> = T extends string
  ? string
  : T extends readonly (infer U)[]
    ? Loose<U>[]
    : T extends object
      ? { [K in keyof T]: Loose<T[K]> }
      : T;

// No extra keys in the fixture: the reverse direction of `satisfies`.
// Every key of T must be a key of Shape (null stripped), recursively.
type Exact<T, Shape> = T extends readonly (infer U)[]
  ? [NonNullable<Shape>] extends [readonly (infer S)[]]
    ? Exact<U, S>[]
    : never
  : T extends object
    ? [NonNullable<Shape>] extends [object]
      ? {
          [K in keyof T]: K extends keyof NonNullable<Shape>
            ? Exact<T[K], NonNullable<Shape>[K]>
            : never;
        }
      : T
    : T;

export const reportSnapshotExample = example satisfies Loose<ReportSnapshot>;
export const reportSnapshotExampleExact = example satisfies Exact<
  typeof example,
  Loose<ReportSnapshot>
>;
