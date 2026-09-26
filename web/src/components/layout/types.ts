interface User {
  name: string;
  email: string;
}

interface BaseNavItem {
  title: string;
  badge?: string;
  icon?: React.ElementType;
}

export type NavItem =
  | (BaseNavItem & {
      items: (BaseNavItem & { url: string })[];
      url?: never;
    })
  | (BaseNavItem & {
      url: string;
      items?: never;
    });

interface NavGroup {
  title: string;
  items: NavItem[];
}

interface SidebarData {
  user: User;
  navGroups: NavGroup[];
}

export type { NavGroup, SidebarData, User };
