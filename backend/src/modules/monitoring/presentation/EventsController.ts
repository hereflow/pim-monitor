import { Controller, Delete, Get, Query, ParseIntPipe, DefaultValuePipe } from '@nestjs/common';
import { EventQueryService }      from '../application/EventQueryService';
import { EventIngestionService }  from '../application/EventIngestionService';
import { MonitorGateway }         from '../infrastructure/MonitorGateway';

@Controller('api/events')
export class EventsController {
  constructor(
    private readonly query:     EventQueryService,
    private readonly ingestion: EventIngestionService,
    private readonly gateway:   MonitorGateway,
  ) {}

  @Get()
  recent(@Query('limit', new DefaultValuePipe(200), ParseIntPipe) limit: number) {
    return this.query.recent(limit);
  }

  @Get('activity')
  activity() {
    return this.query.activity();
  }

  @Get('stats')
  stats() {
    return this.query.stats();
  }

  @Get('alerts')
  alerts() {
    return this.query.alertSummary();
  }

  @Get('hardware')
  hardware(@Query('limit', new DefaultValuePipe(200), ParseIntPipe) limit: number) {
    return this.ingestion.recentHardware(limit);
  }

  @Delete()
  clear() {
    this.query.clearAll();
    this.ingestion.clearHardware();
    this.gateway.broadcastClear();
    return { ok: true };
  }
}
