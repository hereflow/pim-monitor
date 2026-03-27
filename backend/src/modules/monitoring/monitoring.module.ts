import { Module }                from '@nestjs/common';
import { EventEmitterModule }    from '@nestjs/event-emitter';
import { IEventStore }           from './domain/IEventStore';
import { AlertEngine }           from './domain/AlertEngine';
import { EventIngestionService } from './application/EventIngestionService';
import { EventQueryService }     from './application/EventQueryService';
import { InMemoryEventStore }    from './infrastructure/InMemoryEventStore';
import { NamedPipeServer }       from './infrastructure/NamedPipeServer';
import { MonitorGateway }        from './infrastructure/MonitorGateway';
import { EventsController }      from './presentation/EventsController';

@Module({
  imports: [EventEmitterModule.forRoot()],
  providers: [
    AlertEngine,
    EventIngestionService,
    EventQueryService,
    { provide: IEventStore, useClass: InMemoryEventStore },
    NamedPipeServer,
    MonitorGateway,
  ],
  controllers: [EventsController],
})
export class MonitoringModule {}
