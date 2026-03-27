import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import * as net from 'net';
import { EventIngestionService } from '../application/EventIngestionService';

const PIPE_PATH = '\\\\.\\pipe\\proc-monitor';

@Injectable()
export class NamedPipeServer implements OnModuleInit, OnModuleDestroy {
  private server!: net.Server;
  private readonly logger = new Logger(NamedPipeServer.name);

  constructor(private readonly ingestion: EventIngestionService) {}

  onModuleInit(): void {
    this.server = net.createServer(socket => this.accept(socket));
    this.server.on('error', err => this.logger.error(err.message));
    this.server.listen(PIPE_PATH, () => this.logger.log(`Pipe: ${PIPE_PATH}`));
  }

  onModuleDestroy(): void {
    this.server?.close();
  }

  private accept(socket: net.Socket): void {
    this.logger.log('Monitor connected');
    let buf = '';

    socket.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8');
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          this.ingestion.ingest(JSON.parse(trimmed));
        } catch {
          this.logger.warn(`Bad frame: ${trimmed.slice(0, 80)}`);
        }
      }
    });

    socket.on('close', () => this.logger.log('Monitor disconnected'));
    socket.on('error', err => this.logger.warn(err.message));
  }
}
