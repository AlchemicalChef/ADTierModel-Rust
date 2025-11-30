import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { getDomainInfo, getTierCounts, getTierMembers, getTier0Infrastructure, checkTierInitialization, getComplianceStatus } from "../services/tauri";
import { useTierStore } from "../store/tierStore";
import { useSettingsStore, getRefreshIntervalMs } from "../store/settingsStore";
import type { TierLevel } from "../types/tier";

// Hook to fetch domain info and initialize connection
export function useDomainConnection() {
  const { setConnected, setDomainInfo, setError } = useTierStore();

  const query = useQuery({
    queryKey: ["domainInfo"],
    queryFn: getDomainInfo,
    retry: 2,
    staleTime: 60_000, // 1 minute
  });

  useEffect(() => {
    if (query.data) {
      setConnected(query.data.connected);
      setDomainInfo(query.data);
    }
    if (query.error) {
      setConnected(false);
      setError(query.error instanceof Error ? query.error.message : "Connection failed");
    }
  }, [query.data, query.error, setConnected, setDomainInfo, setError]);

  return query;
}

// Hook to fetch tier counts
export function useTierCounts() {
  const { setTierCounts } = useTierStore();

  const query = useQuery({
    queryKey: ["tierCounts"],
    queryFn: getTierCounts,
    staleTime: 30_000, // 30 seconds
    refetchInterval: 60_000, // Refetch every minute
  });

  useEffect(() => {
    if (query.data) {
      setTierCounts(query.data);
    }
  }, [query.data, setTierCounts]);

  return query;
}

// Hook to fetch members of a specific tier
export function useTierMembers(tier: TierLevel | "Unassigned") {
  const { setTierMembers, setLoading } = useTierStore();

  const query = useQuery({
    queryKey: ["tierMembers", tier],
    queryFn: () => getTierMembers(tier),
    staleTime: 30_000, // 30 seconds
  });

  useEffect(() => {
    setLoading(query.isLoading);
  }, [query.isLoading, setLoading]);

  useEffect(() => {
    if (query.data) {
      setTierMembers(tier, query.data);
    }
  }, [query.data, tier, setTierMembers]);

  return query;
}

// Hook to fetch all tiers at once
export function useAllTierData() {
  const tier0Query = useTierMembers("Tier0");
  const tier1Query = useTierMembers("Tier1");
  const tier2Query = useTierMembers("Tier2");
  const unassignedQuery = useTierMembers("Unassigned");

  return {
    isLoading:
      tier0Query.isLoading ||
      tier1Query.isLoading ||
      tier2Query.isLoading ||
      unassignedQuery.isLoading,
    isError:
      tier0Query.isError ||
      tier1Query.isError ||
      tier2Query.isError ||
      unassignedQuery.isError,
    refetch: () => {
      tier0Query.refetch();
      tier1Query.refetch();
      tier2Query.refetch();
      unassignedQuery.refetch();
    },
  };
}

// Hook to fetch Tier 0 infrastructure
export function useTier0Infrastructure() {
  return useQuery({
    queryKey: ["tier0Infrastructure"],
    queryFn: getTier0Infrastructure,
    staleTime: 60_000, // 1 minute
  });
}

// Hook to check initialization status
export function useInitializationStatus() {
  return useQuery({
    queryKey: ["initializationStatus"],
    queryFn: checkTierInitialization,
    staleTime: 300_000, // 5 minutes
    retry: 1,
  });
}

// Hook to auto-refresh all data based on settings
export function useAutoRefresh() {
  const queryClient = useQueryClient();
  const { autoRefreshInterval } = useSettingsStore();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    // Clear existing interval
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    const intervalMs = getRefreshIntervalMs(autoRefreshInterval);
    if (!intervalMs) return;

    // Set up new interval
    intervalRef.current = setInterval(() => {
      // Invalidate queries to trigger refetch
      queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
      queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
      queryClient.invalidateQueries({ queryKey: ["complianceStatus"] });
      queryClient.invalidateQueries({ queryKey: ["domainInfo"] });
    }, intervalMs);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [autoRefreshInterval, queryClient]);
}

// Hook to fetch compliance status with auto-refresh support
export function useComplianceStatus() {
  const { autoRefreshInterval } = useSettingsStore();
  const intervalMs = getRefreshIntervalMs(autoRefreshInterval);

  return useQuery({
    queryKey: ["complianceStatus"],
    queryFn: getComplianceStatus,
    staleTime: 30_000,
    refetchInterval: intervalMs || false,
  });
}
