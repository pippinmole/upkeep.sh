import { redirect } from "next/navigation";

import { settingsSections } from "@/components/layout/settings-sections";

// No settings overview yet: open the first section.
export default function SettingsPage() {
  redirect(settingsSections[0].url);
}
