import { redirect } from "next/navigation";

// "Needs attention" lives on the Machines home page now.
export default function AttentionPage() {
  redirect("/dashboard");
}
