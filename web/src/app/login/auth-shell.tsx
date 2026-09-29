import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

// Brand mark and card shared by the landing, sign-in and sign-up pages.
export function BrandMark() {
  return (
    <Link href="/" className="flex items-center gap-2 text-lg font-semibold tracking-tight">
      <ShieldCheck className="text-primary size-6" aria-hidden />
      upkeep.sh
    </Link>
  );
}

export function AuthShell({
  title,
  description,
  footer,
  children,
}: {
  title: string;
  description: string;
  footer: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="bg-background flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-12">
      <BrandMark />
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-xl">
            <h1>{title}</h1>
          </CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>{children}</CardContent>
        <CardFooter className="text-muted-foreground justify-center text-sm">{footer}</CardFooter>
      </Card>
    </main>
  );
}
