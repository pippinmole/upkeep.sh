"use client";

import { createContext, useContext } from "react";

import type { Role } from "@/lib/roles";

// The signed-in user's role for client components, provided by the
// dashboard layout. UX only: it decides which write controls to show. The
// server re-checks the role on every write (lib/viewer.ts requireAdmin).
type ClientViewer = { role: Role; isAdmin: boolean };

const ViewerContext = createContext<ClientViewer>({ role: "member", isAdmin: false });

export function ViewerProvider({ role, children }: { role: Role; children: React.ReactNode }) {
  return (
    <ViewerContext.Provider value={{ role, isAdmin: role === "admin" }}>
      {children}
    </ViewerContext.Provider>
  );
}

export function useViewer(): ClientViewer {
  return useContext(ViewerContext);
}

// Wraps a write control (an "Add ..." button, a row's action menu) so it
// renders only for admins; members see nothing in its place.
export function adminOnly<P extends object>(Component: React.ComponentType<P>) {
  function AdminOnlyControl(props: P) {
    return useViewer().isAdmin ? <Component {...props} /> : null;
  }
  AdminOnlyControl.displayName = `adminOnly(${Component.displayName ?? Component.name})`;
  return AdminOnlyControl;
}

// Renders children only for admins. For write controls (add, edit, delete
// buttons and menus) that members shouldn't see.
export function AdminOnly({
  children,
  fallback = null,
}: {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}) {
  return useViewer().isAdmin ? children : fallback;
}
