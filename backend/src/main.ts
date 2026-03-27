import { NestFactory } from '@nestjs/core';
import { AppModule }   from './app.module';
import { Logger }      from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({ origin: '*' });
  const port = process.env.PORT ?? 3001;
  await app.listen(port);
  Logger.log(`http://localhost:${port}`, 'Bootstrap');
}

bootstrap();
