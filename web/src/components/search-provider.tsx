"use client";

import { createContext, useContext } from "react";

interface SearchContextType {
  open: boolean;
  setOpen: React.Dispatch<React.SetStateAction<boolean>>;
}

const defaultSearchContext: SearchContextType = {
  open: false,
  setOpen: () => undefined,
};

const SearchContext = createContext<SearchContextType | null>(null);

interface Props {
  children: React.ReactNode;
  value: SearchContextType;
}

// Holds the command menu's open state; the dashboard layout renders the
// menu itself (CommandMenu), since it needs the nav counts and sidebar.
export default function SearchProvider({ children, value }: Props) {
  return <SearchContext.Provider value={value}>{children}</SearchContext.Provider>;
}

export const useSearch = () => {
  return useContext(SearchContext) ?? defaultSearchContext;
};
