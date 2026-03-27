import { useMemo } from 'react';
import { ShieldAlert, AlertTriangle, Zap, KeyRound, Cpu, ShieldOff } from 'lucide-react';
import { ProcessEvent, HardwareEvent } from '../types';
import clsx from 'clsx';

interface Props {
  events: ProcessEvent[];
  hwEvents?: HardwareEvent[];
}

interface Alert {
  id: string;
  message: string;
  detail: string;
  level: 'critical' | 'warning';
  icon: typeof ShieldAlert;
}

const BURST_WINDOW_MS = 5_000;
const BURST_THRESHOLD = 10;

export function AlertBanner({ events, hwEvents = [] }: Props) {
  const alerts = useMemo<Alert[]>(() => {
    const found: Alert[] = [];
    const now    = Date.now();
    const recent = events.filter(e => now - e.ts < BURST_WINDOW_MS);

    const crt = events.filter(e =>
      e.api === 'CreateRemoteThread' || e.api === 'NtCreateThreadEx');
    if (crt.length > 0) {
      const last = crt[crt.length - 1];
      found.push({
        id:      `crt-${last.id}`,
        level:   'critical',
        icon:    ShieldAlert,
        message: 'Remote thread injection detected',
        detail:  `${last.callerName} → ${last.targetName} via ${last.api}`,
      });
    }

    const wpm = recent.filter(e =>
      e.api === 'WriteProcessMemory' || e.api === 'NtWriteVirtualMemory');
    if (wpm.length >= BURST_THRESHOLD) {
      found.push({
        id:      `wpm-burst-${now}`,
        level:   'critical',
        icon:    Zap,
        message: `Memory write burst: ${wpm.length} calls in 5 s`,
        detail:  `Primary caller: ${wpm[0]?.callerName}`,
      });
    }

    const fullAccess = events.filter(
      e => (e.api === 'OpenProcess' || e.api === 'NtOpenProcess')
           && (e.param1 & 0x1F0FFF) === 0x1F0FFF,
    );
    if (fullAccess.length > 0) {
      const last = fullAccess[fullAccess.length - 1];
      found.push({
        id:      `full-access-${last.id}`,
        level:   'warning',
        icon:    KeyRound,
        message: 'PROCESS_ALL_ACCESS granted',
        detail:  `${last.callerName} opened ${last.targetName} with full access`,
      });
    }

    const suspicious = events.filter(e => e.suspiciousCaller);
    if (suspicious.length > 0) {
      const last = suspicious[suspicious.length - 1];
      found.push({
        id:      `suspicious-${last.id}`,
        level:   'critical',
        icon:    AlertTriangle,
        message: 'Call from unbacked memory region',
        detail:  `${last.api} from ${last.callerName} — possible shellcode`,
      });
    }

    const dmaDevices = hwEvents.filter(e => e.hwType === 'DmaDeviceFound');
    if (dmaDevices.length > 0) {
      const worst = dmaDevices.find(e => e.threat === 'dangerous') ?? dmaDevices[0];
      found.push({
        id:      `dma-${worst.id}`,
        level:   'critical',
        icon:    Cpu,
        message: 'DMA/FPGA device detected on PCI bus',
        detail:  `${worst.deviceName} — ${worst.detail}`,
      });
    }

    const iommuBad = hwEvents.filter(e =>
      e.hwType === 'IommuStatus' && e.severity === 'critical');
    if (iommuBad.length > 0) {
      found.push({
        id:      'iommu-disabled',
        level:   'critical',
        icon:    ShieldOff,
        message: 'IOMMU / DMA Protection is DISABLED',
        detail:  'System is vulnerable to DMA-based attacks',
      });
    }

    return found;
  }, [events, hwEvents]);

  if (alerts.length === 0) return null;

  return (
    <div className="flex flex-col gap-2">
      {alerts.map(a => {
        const Icon = a.icon;
        return (
          <div
            key={a.id}
            className={clsx(
              'flex items-start gap-3 px-4 py-3 rounded-lg border font-mono text-xs',
              a.level === 'critical'
                ? 'bg-critical/10 border-critical/30 text-critical'
                : 'bg-warning/10  border-warning/30  text-warning',
            )}
          >
            <div className={clsx(
              'p-1.5 rounded shrink-0 mt-0.5',
              a.level === 'critical' ? 'bg-critical/15' : 'bg-warning/15',
            )}>
              <Icon size={14} />
            </div>
            <div className="min-w-0">
              <div className="font-semibold">{a.message}</div>
              <div className="text-muted mt-0.5 truncate">{a.detail}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
