import { useState, useEffect, useCallback } from 'react';
import { DetectionEvent, detectionManager } from '@/lib/detectionSystems';

/**
 * Hook for real-time event streaming from detection systems
 */

interface UseDetectionEventsOptions {
  enabled?: boolean;
  pollInterval?: number; // milliseconds
  autoStart?: boolean;
}

export function useDetectionEvents(options: UseDetectionEventsOptions = {}) {
  const {
    enabled = true,
    pollInterval = 5000, // 5 seconds
    autoStart = true,
  } = options;

  const [events, setEvents] = useState<DetectionEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(autoStart);
  const [lastUpdate, setLastUpdate] = useState<string>(new Date().toISOString());
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  /**
   * Fetch events from all detection systems
   */
  const fetchEvents = useCallback(async () => {
    if (!enabled) return;

    setIsLoading(true);
    try {
      const newEvents = await detectionManager.getAllEvents();
      setEvents(newEvents);
      setLastUpdate(new Date().toISOString());
      setError(null);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch events';
      setError(errorMessage);
      console.error('Error fetching detection events:', err);
    } finally {
      setIsLoading(false);
    }
  }, [enabled]);

  /**
   * Start streaming events
   */
  const startStreaming = useCallback(() => {
    setIsStreaming(true);
  }, []);

  /**
   * Stop streaming events
   */
  const stopStreaming = useCallback(() => {
    setIsStreaming(false);
  }, []);

  /**
   * Toggle streaming state
   */
  const toggleStreaming = useCallback(() => {
    setIsStreaming((prev) => !prev);
  }, []);

  /**
   * Manually refresh events
   */
  const refresh = useCallback(async () => {
    await fetchEvents();
  }, [fetchEvents]);

  /**
   * Clear all events
   */
  const clear = useCallback(() => {
    setEvents([]);
  }, []);

  /**
   * Set up polling interval
   */
  useEffect(() => {
    if (!isStreaming || !enabled) return;

    // Fetch immediately
    fetchEvents();

    // Set up interval
    const interval = setInterval(() => {
      fetchEvents();
    }, pollInterval);

    return () => clearInterval(interval);
  }, [isStreaming, enabled, pollInterval, fetchEvents]);

  return {
    events,
    isStreaming,
    isLoading,
    error,
    lastUpdate,
    fetchEvents,
    startStreaming,
    stopStreaming,
    toggleStreaming,
    refresh,
    clear,
    eventCount: events.length,
  };
}

/**
 * Hook for filtering and sorting detection events
 */
export function useFilteredDetectionEvents(
  events: DetectionEvent[],
  filters?: {
    severity?: string[];
    sourceSystem?: string[];
    eventType?: string[];
    searchText?: string;
  }
) {
  const [filteredEvents, setFilteredEvents] = useState(events);

  useEffect(() => {
    let result = [...events];

    if (filters?.severity && filters.severity.length > 0) {
      result = result.filter((e) => filters.severity!.includes(e.severity));
    }

    if (filters?.sourceSystem && filters.sourceSystem.length > 0) {
      result = result.filter((e) => filters.sourceSystem!.includes(e.sourceSystem));
    }

    if (filters?.eventType && filters.eventType.length > 0) {
      result = result.filter((e) => filters.eventType!.includes(e.eventType));
    }

    if (filters?.searchText && filters.searchText.length > 0) {
      const search = filters.searchText.toLowerCase();
      result = result.filter(
        (e) =>
          e.title.toLowerCase().includes(search) ||
          e.description.toLowerCase().includes(search) ||
          e.sourceIP?.includes(search) ||
          e.destIP?.includes(search)
      );
    }

    setFilteredEvents(result);
  }, [events, filters]);

  return filteredEvents;
}

/**
 * Hook for aggregating events by source system
 */
export function useEventsBySource(events: DetectionEvent[]) {
  const [eventsBySource, setEventsBySource] = useState<
    Record<string, DetectionEvent[]>
  >({});

  useEffect(() => {
    const grouped: Record<string, DetectionEvent[]> = {};

    events.forEach((event) => {
      if (!grouped[event.sourceSystem]) {
        grouped[event.sourceSystem] = [];
      }
      grouped[event.sourceSystem].push(event);
    });

    setEventsBySource(grouped);
  }, [events]);

  return eventsBySource;
}

/**
 * Hook for tracking event statistics
 */
export function useEventStatistics(events: DetectionEvent[]) {
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    bySeverity: {} as Record<string, number>,
    bySource: {} as Record<string, number>,
    byType: {} as Record<string, number>,
  });

  useEffect(() => {
    const newStats = {
      total: events.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      bySeverity: {} as Record<string, number>,
      bySource: {} as Record<string, number>,
      byType: {} as Record<string, number>,
    };

    events.forEach((event) => {
      // Count by severity
      newStats[event.severity as keyof typeof newStats]++;
      newStats.bySeverity[event.severity] =
        (newStats.bySeverity[event.severity] || 0) + 1;

      // Count by source
      newStats.bySource[event.sourceSystem] =
        (newStats.bySource[event.sourceSystem] || 0) + 1;

      // Count by type
      newStats.byType[event.eventType] =
        (newStats.byType[event.eventType] || 0) + 1;
    });

    setStats(newStats);
  }, [events]);

  return stats;
}
