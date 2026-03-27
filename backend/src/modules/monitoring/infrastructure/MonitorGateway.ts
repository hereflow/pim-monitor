import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  SubscribeMessage,
} from '@nestjs/websockets';
import { OnEvent }                from '@nestjs/event-emitter';
import { Server, Socket }         from 'socket.io';
import { Logger }                 from '@nestjs/common';
import { ProcessEvent }           from '../domain/ProcessEvent';
import { HardwareEvent }          from '../domain/HardwareEvent';
import { EventQueryService }      from '../application/EventQueryService';
import { EventIngestionService }  from '../application/EventIngestionService';

@WebSocketGateway({ cors: { origin: '*' }, namespace: '/monitor' })
export class MonitorGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server!: Server;
  private readonly logger = new Logger(MonitorGateway.name);

  constructor(
    private readonly query:     EventQueryService,
    private readonly ingestion: EventIngestionService,
  ) {}

  handleConnection(client: Socket): void {
    this.logger.log(`Client: ${client.id}`);
    client.emit('history',         this.query.recent(200));
    client.emit('activity',        this.query.activity());
    client.emit('stats',           this.query.stats());
    client.emit('alerts',          this.query.alertSummary());
    client.emit('hardwareHistory', this.ingestion.recentHardware(200));
  }

  handleDisconnect(client: Socket): void {
    this.logger.log(`Disconnect: ${client.id}`);
  }

  @OnEvent('monitor.event')
  onEvent(ev: ProcessEvent): void {
    this.server.emit('event',  ev);
    this.server.emit('stats',  this.query.stats());
    this.server.emit('alerts', this.query.alertSummary());
  }

  @OnEvent('monitor.hardware')
  onHardware(ev: HardwareEvent): void {
    this.server.emit('hardware', ev);
  }

  @SubscribeMessage('getActivity')
  onGetActivity(): void {
    this.server.emit('activity', this.query.activity());
  }

  broadcastClear(): void {
    this.server.emit('clear');
  }
}
