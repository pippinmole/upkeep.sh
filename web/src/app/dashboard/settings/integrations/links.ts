// Settings > Integrations routes. Each tab is its own route under the
// section; API tokens (PR 9) is added here when it lands.
export const INTEGRATIONS_URL = "/dashboard/settings/integrations";

export const INTEGRATION_TABS = [
  { href: INTEGRATIONS_URL, label: "Connect" },
  { href: `${INTEGRATIONS_URL}/connected-apps`, label: "Connected apps" },
  { href: `${INTEGRATIONS_URL}/activity`, label: "Activity" },
];
