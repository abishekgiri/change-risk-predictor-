import { Suspense } from "react";
import { CreatePolicyForm } from "./CreatePolicyForm";

export default function CreatePolicyPage() {
  return (
    <Suspense fallback={<div className="animate-pulse rounded-xl bg-slate-100 h-96" />}>
      <CreatePolicyForm />
    </Suspense>
  );
}
