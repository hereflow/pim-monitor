import { Injectable }   from '@nestjs/common';
import { ProcessEvent } from './ProcessEvent';

export interface Alert {
  id: string;
  level: 'critical' | 'warning';
  rule: string;
  detail: string;
}

const BURST_WINDOW_MS = 5_000;
const BURST_THRESHOLD = 10;

@Injectable()
export class AlertEngine {
  analyse(events: ProcessEvent[]): Alert[] {
    const alerts: Alert[] = [];
    const now    = Date.now();
    const recent = events.filter(e => now - e.ts < BURST_WINDOW_MS);

    const injections = events.filter(e => e.api === 'NtCreateThreadEx' || e.api === 'CreateRemoteThread');
    if (injections.length > 0) {
      const last = injections[injections.length - 1];
      alerts.push({
        id:     `inject-${last.id}`,
        level:  'critical',
        rule:   'Remote thread injection',
        detail: `${last.callerName} → ${last.targetName} via ${last.api}`,
      });
    }

    const writes = recent.filter(e => e.api === 'WriteProcessMemory' || e.api === 'NtWriteVirtualMemory');
    if (writes.length >= BURST_THRESHOLD) {
      alerts.push({
        id:     `write-burst-${now}`,
        level:  'critical',
        rule:   `Memory write burst (${writes.length} in 5 s)`,
        detail: `Caller: ${writes[0]?.callerName}`,
      });
    }

    const suspicious = events.filter(e => e.suspiciousCaller);
    if (suspicious.length > 0) {
      const last = suspicious[suspicious.length - 1];
      alerts.push({
        id:     `suspicious-${last.id}`,
        level:  'critical',
        rule:   'Call from unbacked memory region',
        detail: `${last.api} from ${last.callerName} — possible shellcode`,
      });
    }

    const direct = events.filter(e => e.origin === 'direct');
    if (direct.length > 0) {
      const last = direct[direct.length - 1];
      alerts.push({
        id:     `direct-${last.id}`,
        level:  'warning',
        rule:   'Direct syscall detected (hook bypass attempt)',
        detail: `${last.api} from ${last.callerName}`,
      });
    }

    const fullAccess = events.filter(
      e => (e.api === 'OpenProcess' || e.api === 'NtOpenProcess')
           && (Number(e.param1) & 0x1F0FFF) === 0x1F0FFF,
    );
    if (fullAccess.length > 0) {
      const last = fullAccess[fullAccess.length - 1];
      alerts.push({
        id:     `full-access-${last.id}`,
        level:  'warning',
        rule:   'PROCESS_ALL_ACCESS granted',
        detail: `${last.callerName} → ${last.targetName}`,
      });
    }

    return alerts;
  }
}
