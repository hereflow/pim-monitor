import { Injectable }   from '@nestjs/common';
import { IEventStore }  from '../domain/IEventStore';
import { AlertEngine }  from '../domain/AlertEngine';

@Injectable()
export class EventQueryService {
  constructor(
    private readonly store: IEventStore,
    private readonly alerts: AlertEngine,
  ) {}

  recent(limit: number) {
    return this.store.recent(Math.min(limit, 1000));
  }

  activity() {
    return this.store.activity();
  }

  stats() {
    return this.store.stats();
  }

  alertSummary() {
    return this.alerts.analyse(this.store.recent(500));
  }

  clearAll() {
    this.store.clear();
  }
}
