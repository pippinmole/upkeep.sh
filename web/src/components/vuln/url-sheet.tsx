"use client";

import { useRouter } from "next/navigation";

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

interface Props {
  // Where closing navigates: the current URL without the sheet's param.
  closeHref: string;
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
}

// A Sheet whose open state is a URL search param (?pkg=, ?v=). The server
// page only renders this when the param is present and the data behind it
// passed the ownership check, so the content is server-rendered and the
// sheet is linkable; closing just drops the param.
export function UrlSheet({ closeHref, title, description, children }: Props) {
  const router = useRouter();
  return (
    <Sheet
      defaultOpen
      onOpenChange={(open) => {
        if (!open) router.push(closeHref, { scroll: false });
      }}
    >
      <SheetContent className="flex w-full flex-col gap-4 overflow-y-auto sm:max-w-xl">
        <SheetHeader className="pr-6">
          <SheetTitle className="break-all">{title}</SheetTitle>
          {description && <SheetDescription>{description}</SheetDescription>}
        </SheetHeader>
        {children}
      </SheetContent>
    </Sheet>
  );
}
