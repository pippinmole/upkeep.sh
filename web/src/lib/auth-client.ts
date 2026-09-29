import { usernameClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

// Browser-side Better Auth client. Same origin as the app, so no baseURL.
export const authClient = createAuthClient({
  plugins: [usernameClient()],
});
