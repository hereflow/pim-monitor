import { Injectable }      from '@nestjs/common';
import { EventEmitter2 }  from '@nestjs/event-emitter';
import { IEventStore }     from '../domain/IEventStore';
import { ProcessEvent }    from '../domain/ProcessEvent';
import { HardwareEvent }   from '../domain/HardwareEvent';

@Injectable()
export class EventIngestionService {
  private readonly hwEvents: HardwareEvent[] = [];

  constructor(
    private readonly store: IEventStore,
    private readonly emitter: EventEmitter2,
  ) {}

  ingest(raw: Record<string, unknown>): void {
    if (raw.type === 'hardware') {
      const hw = raw as unknown as HardwareEvent;
      this.hwEvents.push(hw);
      if (this.hwEvents.length > 500) this.hwEvents.shift();
      this.emitter.emit('monitor.hardware', hw);
      return;
    }

    const event = raw as unknown as ProcessEvent;
    this.store.append(event);
    this.emitter.emit('monitor.event', event);
  }

  recentHardware(limit = 200): HardwareEvent[] {
    return this.hwEvents.slice(-limit);
  }

  clearHardware(): void {
    this.hwEvents.length = 0;
  }
}
