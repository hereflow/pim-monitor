import { Module }           from '@nestjs/common';
import { MonitoringModule } from './modules/monitoring/monitoring.module';

@Module({
  imports: [MonitoringModule],
})
export class AppModule {}
