import { LegalPanel } from "@/components/Legal";
import { PageHeader } from "@/components/shared";

export default function Legal() {
  return (
    <div className="h-[calc(100vh-120px)] flex flex-col">
      <PageHeader title="Legal" desc="Terms of use and operating disclaimer" />
      <div className="flex-1 min-h-0">
        <LegalPanel />
      </div>
    </div>
  );
}
