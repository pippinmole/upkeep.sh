"use client";

import { useState, useTransition } from "react";
import { createEnrollmentToken } from "./actions";

export function AddHostButton({ serverUrl }: { serverUrl: string }) {
  const [token, setToken] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  if (token) {
    return (
      <pre className="max-w-full overflow-x-auto rounded bg-neutral-100 p-4 text-xs">
        {`docker run -d --restart unless-stopped \\
  --pid host --network host --read-only \\
  --cap-drop ALL --security-opt no-new-privileges:true \\
  -v /:/host:ro \\
  -e SW_SERVER_URL=${serverUrl} \\
  -e SW_ENROLLMENT_TOKEN=${token} \\
  ghcr.io/icondesk/security-whatnot-agent:latest`}
      </pre>
    );
  }

  return (
    <button
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          setToken(await createEnrollmentToken());
        })
      }
      className="rounded bg-black px-3 py-2 text-white disabled:opacity-50"
    >
      {pending ? "Generating…" : "Add host"}
    </button>
  );
}
