import { useRef, useState, useEffect, useMemo } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { TierMember, TierLevel } from "../../types/tier";
import { TierMemberCard } from "./TierMemberCard";

interface GroupedMembers {
  computers: TierMember[];
  users: TierMember[];
  groups: TierMember[];
}

interface VirtualizedMemberGridProps {
  members: GroupedMembers;
  tier: TierLevel | "Unassigned";
  onRefresh: () => void;
}

type VirtualRow =
  | { type: "header"; title: string; count: number }
  | { type: "cards"; members: TierMember[] };

// Constants for row heights
const ROW_HEIGHT = 180; // Card height + gap
const HEADER_HEIGHT = 48; // Header with padding

export function VirtualizedMemberGrid({
  members,
  tier,
  onRefresh,
}: VirtualizedMemberGridProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [columnCount, setColumnCount] = useState(3);

  // Responsive column calculation using ResizeObserver
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const updateColumns = () => {
      const width = container.clientWidth;
      if (width < 768) {
        setColumnCount(1);
      } else if (width < 1024) {
        setColumnCount(2);
      } else {
        setColumnCount(3);
      }
    };

    // Initial calculation
    updateColumns();

    const observer = new ResizeObserver(() => {
      updateColumns();
    });

    observer.observe(container);
    return () => observer.disconnect();
  }, []);

  // Build flattened rows for virtualization
  const rows = useMemo((): VirtualRow[] => {
    const result: VirtualRow[] = [];

    const addSection = (items: TierMember[], title: string) => {
      if (items.length === 0) return;

      // Add header row
      result.push({ type: "header", title, count: items.length });

      // Add card rows (columnCount items per row)
      for (let i = 0; i < items.length; i += columnCount) {
        result.push({
          type: "cards",
          members: items.slice(i, i + columnCount),
        });
      }
    };

    addSection(members.computers, "Computers");
    addSection(members.users, "Users & Service Accounts");
    addSection(members.groups, "Groups");

    return result;
  }, [members, columnCount]);

  // Virtualizer configuration
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => containerRef.current,
    estimateSize: (index) =>
      rows[index].type === "header" ? HEADER_HEIGHT : ROW_HEIGHT,
    overscan: 5, // Render 5 extra rows above/below viewport for smooth scrolling
  });

  const virtualRows = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();

  // If no content, don't render
  if (rows.length === 0) {
    return null;
  }

  return (
    <div
      ref={containerRef}
      className="overflow-auto"
      style={{
        height: "calc(100vh - 420px)",
        minHeight: "300px",
      }}
    >
      <div
        style={{
          height: totalHeight,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualRows.map((virtualRow) => {
          const row = rows[virtualRow.index];

          return (
            <div
              key={virtualRow.key}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                height: virtualRow.size,
                transform: `translateY(${virtualRow.start}px)`,
              }}
            >
              {row.type === "header" ? (
                <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 pt-4 pb-3">
                  {row.title} ({row.count.toLocaleString()})
                </h3>
              ) : (
                <div
                  className="grid gap-4"
                  style={{
                    gridTemplateColumns: `repeat(${columnCount}, 1fr)`,
                  }}
                >
                  {row.members.map((member) => (
                    <TierMemberCard
                      key={member.distinguishedName}
                      member={member}
                      selectable={tier !== "Unassigned"}
                      onRefresh={onRefresh}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
