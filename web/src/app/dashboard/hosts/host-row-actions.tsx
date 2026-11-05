"use client";

import {
  AlertTriangle,
  Loader2,
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// What the manage dialogs need: both the hosts page rows and the Machines page rows fit.
export type ManagedHost = {
  id: string;
  hostname: string;
  label: string | null;
  archivedAt: string | null;
  duplicateOf: { id: string; hostname: string; label: string | null } | null;
  // The archive and delete dialogs warn about agents that still collect it.
  agents: { name: string; status: string }[];
};

export type ManageDialogKind = "archive" | "unarchive" | "merge" | "dismiss" | "delete";

const display = (h: { hostname: string; label: string | null }) =>
  h.label ? `${h.label} (${h.hostname})` : h.hostname;

// The confirmation dialogs behind a host's manage actions; `open` names the
// one showing. Delete asks for the hostname to be typed.
export function ManageDialogs({
  host,
  open,
  onClose,
}: {
  host: ManagedHost;
  open: ManageDialogKind | null;
  onClose: () => void;
}) {
  const onOpenChange = (next: boolean) => {
    if (!next) onClose();
  };
  const activeAgents = host.agents.filter((a) => a.status === "online" || a.status === "stale");
  return (
    <>
      <ActionDialog
        open={open === "archive"}
        onOpenChange={onOpenChange}
        title={`Archive ${display(host)}?`}
        description={
          <>
            <p>
              The machine is hidden from the machine list and the fleet vulnerability and package
              views. Its history and findings are kept and stay visible on its own pages; its
              findings are left as they are (not resolved).
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
        open={open === "unarchive"}
        onOpenChange={onOpenChange}
        title={`Unarchive ${display(host)}?`}
        description={<p>The machine shows up in lists and fleet views again.</p>}
        actionLabel="Unarchive"
        run={() => setHostArchived(host.id, false)}
      />

      {host.duplicateOf && (
        <>
          <ActionDialog
            open={open === "merge"}
            onOpenChange={onOpenChange}
            title={`Merge into ${display(host.duplicateOf)}?`}
            description={
              <>
                <p>
                  Use this when both are the same machine (typically the agent was reinstalled while
                  the old one was still reporting). The agents collecting {host.hostname} move to{" "}
                  {host.duplicateOf.hostname}: their next pushes continue its history and inventory.
                </p>
                <p>
                  This machine&apos;s own snapshots and findings are not moved: it is archived as
                  &ldquo;merged&rdquo; and its pages stay available. This can&apos;t be undone.
                </p>
              </>
            }
            actionLabel="Merge"
            run={() => mergeHost(host.id, host.duplicateOf!.id)}
          />
          <ActionDialog
            open={open === "dismiss"}
            onOpenChange={onOpenChange}
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
        open={open === "delete"}
        onOpenChange={onOpenChange}
        title={`Delete ${display(host)}?`}
        description={
          <>
            <p>
              Permanently deletes the machine with all its snapshots, package history and findings. Its
              agents are not deleted. This can&apos;t be undone; archive the machine instead to keep
              its history.
            </p>
            {activeAgents.length > 0 && (
              <p className="text-foreground font-medium">
                {activeAgents.map((a) => a.name).join(", ")} still{" "}
                {activeAgents.length === 1 ? "reports" : "report"} this machine, so it will be
                re-created on the next push. Revoke the agent first to remove it for good.
              </p>
            )}
          </>
        }
        actionLabel="Delete machine"
        destructive
        confirmText={host.hostname}
        run={(typed) => deleteHost(host.id, typed)}
      />
    </>
  );
}

export function RenameDialog({
  host,
  open,
  onOpenChange,
}: {
  host: Pick<ManagedHost, "id" | "hostname" | "label">;
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
