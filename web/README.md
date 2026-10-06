This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
bun dev
# or
npm run dev
# or
yarn dev
# or
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## MCP server: checking the sign-in by hand

`/api/mcp` is a read-only MCP server ([docs/MCP.md](../docs/MCP.md)); Claude Code signs in through the
browser (OAuth, CIMD). Against the dev stack (`BETTER_AUTH_URL=http://localhost:3000`), in a scratch directory
so your own config stays untouched:

1. `claude mcp add --transport http --scope project upkeep http://localhost:3000/api/mcp`
2. Start `claude` there, approve the project server, run `/mcp`, pick `upkeep`, choose **Authenticate**.
3. The browser opens on `/login` (or straight on the consent page if you're signed in). Sign in; the consent
   page names "Claude Code (claude.ai)" and the scopes. **Allow** returns you to Claude Code.
4. Ask "summarize my upkeep.sh workspace": Claude calls `get_workspace_summary`. The call shows up in the
   database: `SELECT tool, client_name, error FROM mcp_calls ORDER BY created_at DESC LIMIT 5;`
5. Revoke it under **Settings → Integrations → Connected apps**: **Revoke…** on the Claude Code row deletes the
   consent and that user's access and refresh tokens for the client. Members see and revoke their own rows;
   administrators everyone's. The next tool call gets a 401 (the consent is checked on every call), the refresh
   token is refused (`invalid_grant`), `/mcp` shows the server needs authentication again, and signing in shows
   the consent page again.

   Without the dashboard (a fallback), the same in SQL for every user of the client:

   ```sql
   DELETE FROM oauth_access_tokens  WHERE client_id = 'https://claude.ai/oauth/claude-code-client-metadata';
   DELETE FROM oauth_refresh_tokens WHERE client_id = 'https://claude.ai/oauth/claude-code-client-metadata';
   DELETE FROM oauth_consents       WHERE client_id = 'https://claude.ai/oauth/claude-code-client-metadata';
   ```

6. Clean up: `claude mcp remove --scope project upkeep`.

Also worth a look after step 3: `SELECT scopes FROM oauth_refresh_tokens;` should have a row with
`offline_access`, which means Claude Code asked for a refresh token and stays connected past the one-hour access
token. If it's missing, Claude Code only requested `mcp:read`; note it in the MCP task list.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
