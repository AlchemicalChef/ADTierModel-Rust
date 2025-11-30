import { useMemo } from "react";
import {
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  MinusIcon,
  ChartBarIcon,
} from "@heroicons/react/24/outline";
import {
  useComplianceHistoryStore,
  getTrendDirection,
  getAverageScore,
  getScoreChange,
  type ComplianceSnapshot,
} from "../../store/complianceHistoryStore";

interface ComplianceTrendChartProps {
  days?: number;
}

function MiniBarChart({ snapshots }: { snapshots: ComplianceSnapshot[] }) {
  if (snapshots.length === 0) {
    return (
      <div className="flex items-center justify-center h-24 text-gray-400 dark:text-gray-500 text-sm">
        No historical data available
      </div>
    );
  }

  // Reverse to show oldest to newest (left to right)
  const reversed = [...snapshots].reverse();
  const maxScore = 100;
  const minScore = 0;
  const range = maxScore - minScore;

  return (
    <div className="flex items-end gap-1 h-24">
      {reversed.map((snapshot, index) => {
        const height = ((snapshot.score - minScore) / range) * 100;
        const date = new Date(snapshot.timestamp);
        const isRecent = index === reversed.length - 1;

        const getBarColor = (score: number) => {
          if (score >= 90) return "bg-green-500";
          if (score >= 70) return "bg-amber-500";
          if (score >= 50) return "bg-orange-500";
          return "bg-red-500";
        };

        return (
          <div
            key={snapshot.timestamp}
            className="relative flex-1 group"
            style={{ maxWidth: "20px" }}
          >
            <div
              className={`w-full rounded-t transition-all ${getBarColor(snapshot.score)} ${
                isRecent ? "opacity-100" : "opacity-70 hover:opacity-100"
              }`}
              style={{ height: `${Math.max(height, 4)}%` }}
            />
            {/* Tooltip */}
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 dark:bg-gray-700 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
              <div className="font-medium">{snapshot.score}%</div>
              <div className="text-gray-300">
                {date.toLocaleDateString(undefined, {
                  month: "short",
                  day: "numeric",
                })}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ViolationsStackChart({ snapshots }: { snapshots: ComplianceSnapshot[] }) {
  if (snapshots.length === 0) return null;

  // Reverse to show oldest to newest (left to right)
  const reversed = [...snapshots].reverse();
  const maxViolations = Math.max(...reversed.map((s) => s.totalViolations), 1);

  return (
    <div className="mt-4">
      <h4 className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
        Violations Over Time
      </h4>
      <div className="flex items-end gap-1 h-16">
        {reversed.map((snapshot) => {
          const totalHeight = (snapshot.totalViolations / maxViolations) * 100;
          const criticalPct = snapshot.totalViolations > 0
            ? (snapshot.criticalCount / snapshot.totalViolations) * totalHeight
            : 0;
          const highPct = snapshot.totalViolations > 0
            ? (snapshot.highCount / snapshot.totalViolations) * totalHeight
            : 0;
          const mediumPct = snapshot.totalViolations > 0
            ? (snapshot.mediumCount / snapshot.totalViolations) * totalHeight
            : 0;
          const lowPct = totalHeight - criticalPct - highPct - mediumPct;

          return (
            <div
              key={snapshot.timestamp}
              className="relative flex-1 flex flex-col-reverse group"
              style={{ maxWidth: "20px" }}
            >
              {snapshot.totalViolations > 0 ? (
                <>
                  {lowPct > 0 && (
                    <div
                      className="w-full bg-blue-400 rounded-b"
                      style={{ height: `${lowPct}%` }}
                    />
                  )}
                  {mediumPct > 0 && (
                    <div
                      className="w-full bg-amber-400"
                      style={{ height: `${mediumPct}%` }}
                    />
                  )}
                  {highPct > 0 && (
                    <div
                      className="w-full bg-orange-400"
                      style={{ height: `${highPct}%` }}
                    />
                  )}
                  {criticalPct > 0 && (
                    <div
                      className="w-full bg-red-500 rounded-t"
                      style={{ height: `${criticalPct}%` }}
                    />
                  )}
                </>
              ) : (
                <div className="w-full h-1 bg-gray-200 dark:bg-gray-700 rounded" />
              )}
              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 dark:bg-gray-700 text-white text-xs rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
                <div className="font-medium">{snapshot.totalViolations} violations</div>
                {snapshot.criticalCount > 0 && (
                  <div className="text-red-300">{snapshot.criticalCount} critical</div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ComplianceTrendChart({ days = 30 }: ComplianceTrendChartProps) {
  const { snapshots: allSnapshots } = useComplianceHistoryStore();

  const snapshots = useMemo(() => {
    return allSnapshots.slice(0, days);
  }, [allSnapshots, days]);

  const trend = getTrendDirection(snapshots);
  const avgScore = getAverageScore(snapshots);
  const scoreChange = getScoreChange(snapshots);

  const TrendIcon =
    trend === "up"
      ? ArrowTrendingUpIcon
      : trend === "down"
      ? ArrowTrendingDownIcon
      : MinusIcon;

  const trendColor =
    trend === "up"
      ? "text-green-600 dark:text-green-400"
      : trend === "down"
      ? "text-red-600 dark:text-red-400"
      : "text-gray-600 dark:text-gray-400";

  return (
    <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-2">
          <ChartBarIcon className="w-4 h-4" />
          Compliance Trend ({days} days)
        </h3>
        {snapshots.length > 0 && (
          <div className="flex items-center gap-2">
            <TrendIcon className={`w-4 h-4 ${trendColor}`} />
            <span className={`text-sm font-medium ${trendColor}`}>
              {scoreChange > 0 ? "+" : ""}
              {scoreChange}%
            </span>
          </div>
        )}
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-4 mb-4">
        <div className="text-center p-2 bg-gray-50 dark:bg-surface-900 rounded-lg">
          <p className="text-lg font-bold text-gray-900 dark:text-white">
            {snapshots[0]?.score ?? "-"}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Current</p>
        </div>
        <div className="text-center p-2 bg-gray-50 dark:bg-surface-900 rounded-lg">
          <p className="text-lg font-bold text-gray-900 dark:text-white">
            {avgScore}%
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Average</p>
        </div>
        <div className="text-center p-2 bg-gray-50 dark:bg-surface-900 rounded-lg">
          <p className="text-lg font-bold text-gray-900 dark:text-white">
            {snapshots.length}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Data Points</p>
        </div>
      </div>

      {/* Score Chart */}
      <div className="mb-2">
        <h4 className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
          Compliance Score
        </h4>
        <MiniBarChart snapshots={snapshots} />
      </div>

      {/* Violations Stacked Chart */}
      <ViolationsStackChart snapshots={snapshots} />

      {/* Legend */}
      <div className="flex flex-wrap gap-3 mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-red-500" />
          <span className="text-xs text-gray-500 dark:text-gray-400">Critical</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-orange-400" />
          <span className="text-xs text-gray-500 dark:text-gray-400">High</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-amber-400" />
          <span className="text-xs text-gray-500 dark:text-gray-400">Medium</span>
        </div>
        <div className="flex items-center gap-1">
          <div className="w-2 h-2 rounded-full bg-blue-400" />
          <span className="text-xs text-gray-500 dark:text-gray-400">Low</span>
        </div>
      </div>
    </div>
  );
}
