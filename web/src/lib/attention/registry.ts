import { channels } from "./providers/channels";
import { collectors } from "./providers/collectors";
import { duplicates } from "./providers/duplicates";
import { endOfLife } from "./providers/eol";
import {
  criticalImages,
  failedDeliveries,
  firingAlerts,
  neverConnected,
  rebootRequired,
  staleHosts,
  waitingHosts,
} from "./providers/estate";
import { vulnerabilities } from "./providers/vulns";
import { type AnyAttentionProvider, defineProvider } from "./types";

// Every "Needs attention" item kind. Items rank by severity, then by the
// order here, so list the more important providers first.
//
// Adding a kind: write a provider in providers/ (a query filtered through
// owner.ts, and a pure map to items), add a mapping test in
// attention.test.ts, and list it here. See docs/NEEDS_ATTENTION.md.
export const ATTENTION_PROVIDERS: AnyAttentionProvider[] = [
  defineProvider(vulnerabilities), // kev (critical), critical-fixable (high)
  defineProvider(collectors), // host-sockets (critical), collectors (medium)
  defineProvider(criticalImages), // high
  defineProvider(firingAlerts), // high
  defineProvider(staleHosts), // high
  defineProvider(endOfLife), // eol (high), eol-soon (low)
  defineProvider(rebootRequired), // medium
  defineProvider(failedDeliveries), // medium
  defineProvider(duplicates), // medium
  defineProvider(neverConnected), // low
  defineProvider(channels), // low
  defineProvider(waitingHosts), // low
];
