import { useEffect, useRef, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { ProcessEvent, ActivitySnapshot, Stats, HardwareEvent } from '../types';

const SOCKET_URL   = 'http://localhost:3001';
const MAX_EVENTS   = 500;
const MAX_HW       = 200;

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected';

export function useMonitor() {
  const [events,     setEvents]     = useState<ProcessEvent[]>([]);
  const [hwEvents,   setHwEvents]   = useState<HardwareEvent[]>([]);
  const [activity,   setActivity]   = useState<ActivitySnapshot[]>([]);
  const [stats,      setStats]      = useState<Stats | null>(null);
  const [status,     setStatus]     = useState<ConnectionStatus>('connecting');
  const socketRef = useRef<Socket | null>(null);

  const clearEvents = useCallback(async () => {
    await fetch(`${SOCKET_URL}/api/events`, { method: 'DELETE' });
  }, []);

  useEffect(() => {
    const socket = io(`${SOCKET_URL}/monitor`, { transports: ['websocket'] });
    socketRef.current = socket;

    socket.on('connect',       () => setStatus('connected'));
    socket.on('disconnect',    () => setStatus('disconnected'));
    socket.on('connect_error', () => setStatus('disconnected'));

    socket.on('history', (history: ProcessEvent[]) => {
      setEvents(history.slice(-MAX_EVENTS));
    });

    socket.on('event', (ev: ProcessEvent) => {
      setEvents(prev => {
        const next = [...prev, ev];
        return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
      });
    });

    socket.on('hardwareHistory', (history: HardwareEvent[]) => {
      setHwEvents(history.slice(-MAX_HW));
    });

    socket.on('hardware', (ev: HardwareEvent) => {
      setHwEvents(prev => {
        const next = [...prev, ev];
        return next.length > MAX_HW ? next.slice(-MAX_HW) : next;
      });
    });

    socket.on('clear', () => {
      setEvents([]);
      setHwEvents([]);
      setActivity([]);
      setStats(null);
    });

    socket.on('activity', (snap: ActivitySnapshot[]) => setActivity(snap));
    socket.on('stats',    (s: Stats) => setStats(s));

    return () => { socket.disconnect(); };
  }, []);

  return { events, hwEvents, activity, stats, status, clearEvents };
}
