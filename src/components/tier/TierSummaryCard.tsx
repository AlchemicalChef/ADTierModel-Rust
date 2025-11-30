import {
  ComputerDesktopIcon,
  UserIcon,
  UserGroupIcon,
} from "@heroicons/react/24/outline";
import { tierConfig } from "../../types/tier";
import type { TierLevel } from "../../types/tier";

interface TierSummaryCardProps {
  title: string;
  count: number;
  tier: TierLevel | "Unassigned";
  icon: "computer" | "user" | "group";
}

const icons = {
  computer: ComputerDesktopIcon,
  user: UserIcon,
  group: UserGroupIcon,
};

export function TierSummaryCard({ title, count, tier, icon }: TierSummaryCardProps) {
  const config = tierConfig[tier];
  const Icon = icons[icon];

  return (
    <div
      className={`rounded-lg border p-4 ${config.bgColor} ${config.borderColor}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center bg-white/50 dark:bg-black/20`}
          >
            <Icon className={`w-5 h-5 ${config.iconColor}`} />
          </div>
          <div>
            <p className={`text-sm font-medium ${config.textColor}`}>{title}</p>
            <p className={`text-2xl font-bold ${config.textColor}`}>{count}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
