import { Injectable }                     from '@nestjs/common';
import { IEventStore, EventStats }        from '../domain/IEventStore';
import { ProcessEvent, ActivityBucket }   from '../domain/ProcessEvent';

const MAX_EVENTS    = 10_000;
const BUCKET_MS     = 1_000;
const ACTIVITY_KEEP = 60;

@Injectable()
export class InMemoryEventStore extends IEventStore {
  private readonly events: ProcessEvent[]             = [];
  private readonly buckets = new Map<number, ActivityBucket>();

  append(event: ProcessEvent): void {
    if (this.events.length >= MAX_EVENTS) this.events.shift();
    this.events.push(event);
    this.updateBucket(event);
  }

  recent(limit: number): ProcessEvent[] {
    return this.events.slice(-limit);
  }

  activity(): ActivityBucket[] {
    return Array.from(this.buckets.values()).sort((a, b) => a.ts - b.ts);
  }

  clear(): void {
    this.events.length = 0;
    this.buckets.clear();
  }

  stats(): EventStats {
    const total      = this.events.length;
    const critical   = this.events.filter(e => e.severity === 'critical').length;
    const warning    = this.events.filter(e => e.severity === 'warning').length;
    const suspicious = this.events.filter(e => e.suspiciousCaller).length;
    return {
      total, critical, warning, suspicious,
      info: total - critical - warning,
      uniqueCallers: new Set(this.events.map(e => e.callerName)).size,
      uniqueTargets: new Set(this.events.map(e => e.targetName)).size,
    };
  }

  private updateBucket(ev: ProcessEvent): void {
    const key = Math.floor(ev.ts / BUCKET_MS) * BUCKET_MS;
    const b   = this.buckets.get(key) ?? { ts: key, info: 0, warning: 0, critical: 0, total: 0 };
    b[ev.severity]++;
    b.total++;
    this.buckets.set(key, b);

    const cutoff = Date.now() - ACTIVITY_KEEP * BUCKET_MS;
    for (const [k] of this.buckets) {
      if (k < cutoff) this.buckets.delete(k);
    }
  }
}
