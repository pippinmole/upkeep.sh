"use client";

import Form from "next/form";
import { Search } from "lucide-react";
import { useRef } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

// A generic select filter. `value: null` selects the "all" sentinel
// (filterParam treats "all" as unset); allLabel omitted = no "all" item.
export type SelectFilter = {
  name: string;
  label: string; // aria-label
  value: string | null;
  allLabel?: string;
  options: { value: string; label: string }[];
  className?: string;
};

interface Props {
  action: string;
  q: string | null;
  qPlaceholder: string;
  qLabel?: string;
  ecosystem?: { value: string | null; options: string[] };
  selects?: SelectFilter[];
  // Params to carry through a submit unchanged (e.g. status=resolved).
  hidden?: Record<string, string | null>;
  sort?: { value: string; options: { value: string; label: string }[] };
  // Point-in-time date input (YYYY-MM-DD); omitted = not offered.
  at?: { value: string | null };
}

// GET form over URL search params (DOMAIN_MODEL.md §3, Q11). next/form
// does client-side navigation and still works without JS (Radix Select
// renders a hidden native <select> with the same name). Submitting drops
// ?page, so a new filter always starts at page 1.
export function FilterBar({
  action,
  q,
  qPlaceholder,
  qLabel = "Search packages",
  ecosystem,
  selects,
  hidden,
  sort,
  at,
}: Props) {
  const formRef = useRef<HTMLFormElement>(null);
  const submit = () => formRef.current?.requestSubmit();

  return (
    <Form ref={formRef} action={action} className="flex flex-wrap items-center gap-2">
      <div className="relative w-full sm:w-64">
        <Search className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
        <Input
          name="q"
          type="search"
          defaultValue={q ?? ""}
          placeholder={qPlaceholder}
          className="pl-8"
          aria-label={qLabel}
        />
      </div>
      {hidden &&
        Object.entries(hidden).map(([k, v]) =>
          v ? <input key={k} type="hidden" name={k} value={v} /> : null,
        )}
      {ecosystem && ecosystem.options.length > 1 && (
        <Select
          name="ecosystem"
          defaultValue={ecosystem.value ?? "all"}
          onValueChange={() => setTimeout(submit)}
        >
          <SelectTrigger className="w-40" aria-label="Ecosystem">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All ecosystems</SelectItem>
            {ecosystem.options.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      {selects?.map((f) => (
        <Select
          key={f.name}
          name={f.name}
          defaultValue={f.value ?? (f.allLabel ? "all" : f.options[0]?.value)}
          onValueChange={() => setTimeout(submit)}
        >
          <SelectTrigger className={f.className ?? "w-40"} aria-label={f.label}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {f.allLabel && <SelectItem value="all">{f.allLabel}</SelectItem>}
            {f.options.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ))}
      {sort && (
        <Select name="sort" defaultValue={sort.value} onValueChange={() => setTimeout(submit)}>
          <SelectTrigger className="w-40" aria-label="Sort">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {sort.options.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      {at && (
        <label className="text-muted-foreground flex items-center gap-2 text-sm">
          As of
          <Input
            name="at"
            type="date"
            defaultValue={at.value ?? ""}
            className="w-40"
            aria-label="Show inventory as of date"
          />
        </label>
      )}
      <Button type="submit" variant="secondary">
        Apply
      </Button>
    </Form>
  );
}
