// Settings > Integrations routes. Each tab is its own route under the
// section.
export const INTEGRATIONS_URL = "/dashboard/settings/integrations";
export const CONNECTED_APPS_URL = `${INTEGRATIONS_URL}/connected-apps`;
export const API_TOKENS_URL = `${INTEGRATIONS_URL}/api-tokens`;

export const INTEGRATION_TABS = [
  { href: INTEGRATIONS_URL, label: "Connect" },
  { href: CONNECTED_APPS_URL, label: "Connected apps" },
  { href: API_TOKENS_URL, label: "API tokens" },
  { href: `${INTEGRATIONS_URL}/activity`, label: "Activity" },
];
