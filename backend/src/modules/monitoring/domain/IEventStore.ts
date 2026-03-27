import { ProcessEvent, ActivityBucket } from './ProcessEvent';

export interface EventStats {
  total: number;
  critical: number;
  warning: number;
  info: number;
  suspicious: number;
  uniqueCallers: number;
  uniqueTargets: number;
}

export abstract class IEventStore {
  abstract append(event: ProcessEvent): void;
  abstract recent(limit: number): ProcessEvent[];
  abstract activity(): ActivityBucket[];
  abstract stats(): EventStats;
  abstract clear(): void;
}
