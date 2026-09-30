"use client";

import {
  AlertTriangle,
  Archive,
  ArchiveRestore,
  Combine,
  Loader2,
  MoreHorizontal,
  Pencil,
  SplitSquareHorizontal,
  Trash2,
} from "lucide-react";
import { useState, useTransition } from "react";

import {
  deleteHost,
  dismissDuplicate,
  mergeHost,
  renameHost,
  setHostArchived,
} from "@/app/dashboard/manage-actions";
import { ActionDialog } from "@/components/action-dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { HostListRow } from "@/lib/queries";
import { adminOnly } from "@/components/viewer-context";

type DialogKind = "rename" | "archive" | "unarchive" | "merge" | "dismiss" | "delete";

const display = (h: { hostname: string; label: string | null }) =>
  h.label ? `${h.label} (${h.hostname})` : h.hostname;

// Per-host management (DOMAIN_MODEL.md §4.3 "Management"): rename,
// archive / unarchive, resolve a duplicate flag (merge / not a duplicate),
// delete. Every action is a server action re-checking ownership.
function HostRowActionsControl({ host }: { host: HostListRow }) {
  const [dialog, setDialog] = useState<DialogKind | null>(null);
  const set = (d: DialogKind) => (open: boolean) => setDialog(open ? d : null);
  const archived = !!host.archivedAt;
  const activeAgents = host.agents.filter((a) => a.status === "online" || a.status === "stale");

  return (
    <>
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label={`Actions for ${host.hostname}`}
          >
            <MoreHorizontal className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="truncate">{display(host)}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setDialog("rename")}>
            <Pencil />
            Rename
          </DropdownMenuItem>
          {host.duplicateOf && !archived && (
            <>
              <DropdownMenuItem onSelect={() => setDialog("merge")}>
                <Combine />
                Merge into {host.duplicateOf.hostname}
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setDialog("dismiss")}>
                <SplitSquareHorizontal />
                Not a duplicate
              </DropdownMenuItem>
            </>
          )}
          {archived ? (
            !host.mergedInto && (
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
          <DropdownMenuItem
            onSelect={() => setDialog("delete")}
            className="text-destructive focus:text-destructive"
          >
            <Trash2 />
            Delete
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <RenameDialog host={host} open={dialog === "rename"} onOpenChange={set("rename")} />

      <ActionDialog
        open={dialog === "archive"}
        onOpenChange={set("archive")}
        title={`Archive ${display(host)}?`}
        description={
          <>
            <p>
              The host is hidden from the host list, the overview and the fleet vulnerability and
              package views. Its history and findings are kept and stay visible on its own pages;
              its findings are left as they are (not resolved).
            </p>
            {activeAgents.length > 0 && (
              <p>
                {activeAgents.map((a) => a.name).join(", ")} still{" "}
                {activeAgents.length === 1 ? "collects" : "collect"} it: new pushes keep being
                recorded without unarchiving it. Revoke the agent to stop collection.
              </p>
            )}
          </>
        }
        actionLabel="Archive"
        run={() => setHostArchived(host.id, true)}
      />
      <ActionDialog
        open={dialog === "unarchive"}
        onOpenChange={set("unarchive")}
        title={`Unarchive ${display(host)}?`}
        description={<p>The host shows up in lists and fleet views again.</p>}
        actionLabel="Unarchive"
        run={() => setHostArchived(host.id, false)}
      />

      {host.duplicateOf && (
        <>
          <ActionDialog
            open={dialog === "merge"}
            onOpenChange={set("merge")}
            title={`Merge into ${display(host.duplicateOf)}?`}
            description={
              <>
                <p>
                  Use this when both are the same machine (typically the agent was reinstalled while
                  the old one was still reporting). The agents collecting {host.hostname} move to{" "}
                  {host.duplicateOf.hostname}: their next pushes continue its history and inventory.
                </p>
                <p>
                  This host&apos;s own snapshots and findings are not moved: it is archived as
                  &ldquo;merged&rdquo; and its pages stay available. This can&apos;t be undone.
                </p>
              </>
            }
            actionLabel="Merge"
            run={() => mergeHost(host.id, host.duplicateOf!.id)}
          />
          <ActionDialog
            open={dialog === "dismiss"}
            onOpenChange={set("dismiss")}
            title="Not a duplicate?"
            description={
              <p>
                {host.hostname} and {host.duplicateOf.hostname} report the same machine identity
                (for example a VM cloned from one template). Mark them as separate machines: the
                &ldquo;Possible duplicate&rdquo; flag is cleared and won&apos;t come back for this
                pair. Consider regenerating the clone&apos;s <code>/etc/machine-id</code>.
              </p>
            }
            actionLabel="Keep separate"
            run={() => dismissDuplicate(host.id)}
          />
        </>
      )}

      <ActionDialog
        open={dialog === "delete"}
        onOpenChange={set("delete")}
        title={`Delete ${display(host)}?`}
        description={
          <>
            <p>
              Permanently deletes the host with all its snapshots, package history and findings. Its
              agents are not deleted. This can&apos;t be undone; archive the host instead to keep
              its history.
            </p>
            {activeAgents.length > 0 && (
              <p className="text-foreground font-medium">
                {activeAgents.map((a) => a.name).join(", ")} still{" "}
                {activeAgents.length === 1 ? "reports" : "report"} this host, so it will be
                re-created on the next push. Revoke the agent first to remove it for good.
              </p>
            )}
          </>
        }
        actionLabel="Delete host"
        destructive
        confirmText={host.hostname}
        run={(typed) => deleteHost(host.id, typed)}
      />
    </>
  );
}

function RenameDialog({
  host,
  open,
  onOpenChange,
}: {
  host: HostListRow;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [label, setLabel] = useState(host.label ?? "");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  function change(next: boolean) {
    if (pending) return;
    onOpenChange(next);
    setLabel(host.label ?? "");
    setError(null);
  }

  function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const res = await renameHost(host.id, label);
      if (res.ok) change(false);
      else setError(res.error);
    });
  }

  return (
    <Dialog open={open} onOpenChange={change}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={save} className="flex flex-col gap-4">
          <DialogHeader>
            <DialogTitle>Rename {host.hostname}</DialogTitle>
            <DialogDescription>
              A display name shown next to the hostname. The hostname itself is what the agent
              reports and updates on every push. Leave empty to show only the hostname.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="host-label">Name</Label>
            <Input
              id="host-label"
              value={label}
              maxLength={100}
              placeholder={host.hostname}
              onChange={(e) => setLabel(e.target.value)}
            />
          </div>
          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={pending}
              onClick={() => change(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// Write controls: admins only (docs/MEMBERS.md); the server re-checks.
export const HostRowActions = adminOnly(HostRowActionsControl);
