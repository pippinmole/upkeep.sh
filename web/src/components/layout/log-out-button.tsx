import { logOut } from "./actions";

// A plain "Log out" link-style button, for pages outside the dashboard.
export function LogOutButton() {
  return (
    <form action={logOut}>
      <button type="submit" className="text-foreground font-medium hover:underline">
        Log out
      </button>
    </form>
  );
}
