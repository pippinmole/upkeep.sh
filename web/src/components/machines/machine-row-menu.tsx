"use client";

import {
  Archive,
  ArchiveRestore,
  Check,
  Combine,
  Copy,
  Download,
  MoreVertical,
  Pencil,
  SplitSquareHorizontal,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  type ManageDialogKind,
  ManageDialogs,
  RenameDialog,
} from "@/app/dashboard/hosts/host-row-actions";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useViewer } from "@/components/viewer-context";
import type { MachineRow } from "@/lib/machines";

type DialogKind = "rename" | ManageDialogKind;

// A row's "⋯" menu (spec §6.2.1). Copy and export are read-only, so members
// see the menu with just those; the changing items are admin-only (the
// server re-checks). The trigger sits above the row's link overlay
// (relative z-10), so opening it never navigates.
export function MachineRowMenu({ machine }: { machine: MachineRow }) {
  const { isAdmin } = useViewer();
  const [dialog, setDialog] = useState<DialogKind | null>(null);
  const name = machine.label ?? machine.hostname;
  const archived = machine.archivedAt !== null;

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="relative z-10 size-8"
            aria-label={`Actions for ${name}`}
          >
            <MoreVertical className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuLabel className="truncate">{name}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <CopyItem text={machine.hostname}>Copy hostname</CopyItem>
          {machine.ip && <CopyItem text={machine.ip}>Copy IP</CopyItem>}
          <DropdownMenuItem asChild>
            <a href={`/dashboard/hosts/${machine.id}/vulnerabilities/export`} download>
              <Download />
              Export vulnerabilities (CSV)
            </a>
          </DropdownMenuItem>
          {isAdmin && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => setDialog("rename")}>
                <Pencil />
                Rename
              </DropdownMenuItem>
              {machine.duplicateOf && !archived && (
                <>
                  <DropdownMenuItem onSelect={() => setDialog("merge")}>
                    <Combine />
                    <span className="truncate">Merge into {machine.duplicateOf.hostname}</span>
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => setDialog("dismiss")}>
                    <SplitSquareHorizontal />
                    Not a duplicate
                  </DropdownMenuItem>
                </>
              )}
              {archived ? (
                // A merged machine stays archived: its agents moved on.
                !machine.mergedInto && (
                  <DropdownMenuItem onSelect={() => setDialog("unarchive")}>
                    <ArchiveRestore />
                    Unarchive
                  </DropdownMenuItem>
                )
              ) : (
                <DropdownMenuItem onSelect={() => setDialog("archive")}>
                  <Archive />
                  Archive
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onSelect={() => setDialog("delete")}>
                <Trash2 />
                Delete
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {isAdmin && (
        <>
          <RenameDialog
            host={machine}
            open={dialog === "rename"}
            onOpenChange={(open) => setDialog(open ? "rename" : null)}
          />
          <ManageDialogs
            host={machine}
            open={dialog === "rename" ? null : dialog}
            onClose={() => setDialog(null)}
          />
        </>
      )}
    </>
  );
}

// Copies on select and keeps the menu open for 1.5s to show "Copied", or
// "Couldn't copy" when the clipboard is unavailable (insecure context,
// denied permission); the app has no toaster.
function CopyItem({ text, children }: { text: string; children: React.ReactNode }) {
  const [result, setResult] = useState<"copied" | "failed" | null>(null);

  useEffect(() => {
    if (!result) return;
    const id = setTimeout(() => setResult(null), 1500);
    return () => clearTimeout(id);
  }, [result]);

  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(text);
      setResult("copied");
    } catch {
      setResult("failed");
    }
  }

  return (
    <DropdownMenuItem
      onSelect={(e) => {
        e.preventDefault();
        void copy();
      }}
    >
      {result === "copied" ? (
        <>
          <Check className="text-success" />
          Copied
        </>
      ) : result === "failed" ? (
        <>
          <X className="text-destructive" />
          Couldn&apos;t copy
        </>
      ) : (
        <>
          <Copy />
          {children}
        </>
      )}
    </DropdownMenuItem>
  );
}
