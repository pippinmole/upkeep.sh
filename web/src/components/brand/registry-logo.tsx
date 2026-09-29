import { Box, Container, type LucideIcon } from "lucide-react";

import { registryOf } from "@/lib/image-key";
import { cn } from "@/lib/utils";

import { MarkOrIcon } from "./brand-mark";
import type { BrandMarkName } from "./marks";

type RegistryInfo = { name: string; mark?: BrandMarkName; icon?: LucideIcon };

// Registry host → display name and mark. Quay, ECR and self-hosted
// registries have no mark in Simple Icons and use the lucide fallback.
function registryInfo(host: string): RegistryInfo {
  if (host === "docker.io") return { name: "Docker Hub", mark: "docker" };
  if (host === "ghcr.io") return { name: "GitHub Container Registry", mark: "github" };
  if (host === "registry.gitlab.com") return { name: "GitLab Container Registry", mark: "gitlab" };
  if (host === "gcr.io" || host.endsWith(".gcr.io") || host.endsWith(".pkg.dev")) {
    return { name: "Google Cloud", mark: "googlecloud" };
  }
  if (host === "quay.io") return { name: "Quay" };
  if (/\.dkr\.ecr\.[^.]+\.amazonaws\.com$/.test(host) || host === "public.ecr.aws") {
    return { name: "Amazon ECR" };
  }
  return { name: host };
}

// The registry an image repository lives on, as an icon and optionally the
// host name. `_untagged` / empty repos (images with no tag) get a muted box.
export function RegistryLogo({
  repo,
  size = 16,
  colored = false,
  showHost = false,
  className,
}: {
  repo: string | null | undefined;
  size?: number;
  colored?: boolean;
  showHost?: boolean;
  className?: string;
}) {
  const host = repo && repo !== "_untagged" ? registryOf(repo) : "";
  const info: RegistryInfo = host ? registryInfo(host) : { name: "Untagged image", icon: Box };
  const labelled = showHost && host !== "";
  const icon = (
    <MarkOrIcon
      mark={info.mark}
      fallback={info.icon ?? Container}
      size={size}
      colored={colored}
      title={labelled ? "" : info.name}
      className={cn(!host && "text-muted-foreground", !labelled && className)}
    />
  );
  if (!labelled) return icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)} title={info.name}>
      {icon}
      <span>{host}</span>
    </span>
  );
}
