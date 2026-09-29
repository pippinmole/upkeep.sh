import { toNextJsHandler } from "better-auth/next-js";

import { authServer } from "@/lib/auth";

export const { GET, POST } = toNextJsHandler(authServer);
