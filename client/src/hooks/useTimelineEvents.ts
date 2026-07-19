import { useState, useEffect, useCallback } from 'react';

export interface TimelineEvent {
  time: string;
  event: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: string;
  details: string;
  isNew?: boolean;
}

interface UseTimelineEventsProps {
  initialEvents: TimelineEvent[];
  enableRealTime?: boolean;
}

/**
 * Hook for managing real-time timeline events
 * Simulates incoming detection events and automatically appends them to the timeline
 */
export function useTimelineEvents({
  initialEvents,
  enableRealTime = true,
}: UseTimelineEventsProps) {
  const [events, setEvents] = useState<TimelineEvent[]>(initialEvents);
  const [isLive, setIsLive] = useState(enableRealTime);
  const [eventCount, setEventCount] = useState(initialEvents.length);

  // Simulated new events that could come from the detection engine
  const simulatedEvents: Omit<TimelineEvent, 'isNew'>[] = [
    {
      time: '2026-07-04 14:33:45',
      event: 'Firewall Rule Updated',
      severity: 'medium',
      source: 'Firewall',
      details: 'New firewall rule created to block source IP range 203.0.113.0/24',
    },
    {
      time: '2026-07-04 14:34:12',
      event: 'Threat Intelligence Match',
      severity: 'high',
      source: 'Threat Feed',
      details: 'Source IP matched known botnet C2 infrastructure from OSINT feed',
    },
    {
      time: '2026-07-04 14:34:58',
      event: 'Endpoint Isolation',
      severity: 'critical',
      source: 'EDR',
      details: 'Suspicious process terminated and endpoint network isolation enabled',
    },
    {
      time: '2026-07-04 14:35:33',
      event: 'Forensic Snapshot',
      severity: 'medium',
      source: 'SOAR',
      details: 'Memory dump and disk snapshot collected for post-incident analysis',
    },
    {
      time: '2026-07-04 14:36:15',
      event: 'Incident Escalated',
      severity: 'critical',
      source: 'SOAR',
      details: 'Incident escalated to incident commander due to multiple critical events',
    },
  ];

  // Add new event to timeline
  const addEvent = useCallback((newEvent: TimelineEvent) => {
    setEvents((prevEvents) => [newEvent, ...prevEvents]);
    setEventCount((prev) => prev + 1);
  }, []);

  // Toggle real-time updates
  const toggleRealTime = useCallback(() => {
    setIsLive((prev) => !prev);
  }, []);

  // Simulate real-time event stream
  useEffect(() => {
    if (!isLive) return;

    let eventIndex = 0;
    const intervals: NodeJS.Timeout[] = [];

    // Schedule simulated events at intervals
    const scheduleNextEvent = () => {
      if (eventIndex < simulatedEvents.length) {
        const delay = Math.random() * 8000 + 4000; // 4-12 seconds between events
        const timeout = setTimeout(() => {
          const baseEvent = simulatedEvents[eventIndex];
          const eventWithNewFlag: TimelineEvent = {
            ...baseEvent,
            isNew: true,
          };
          addEvent(eventWithNewFlag);
          eventIndex++;
          scheduleNextEvent();
        }, delay);
        intervals.push(timeout);
      }
    };

    scheduleNextEvent();

    return () => {
      intervals.forEach((interval) => clearTimeout(interval));
    };
  }, [isLive, addEvent]);

  // Remove 'isNew' flag after animation completes
  useEffect(() => {
    const timer = setTimeout(() => {
      setEvents((prevEvents) =>
        prevEvents.map((event) => ({
          ...event,
          isNew: false,
        }))
      );
    }, 1000);

    return () => clearTimeout(timer);
  }, [eventCount]);

  return {
    events,
    isLive,
    toggleRealTime,
    addEvent,
    eventCount,
  };
}
