import { useMemo } from 'react';
import { format } from 'date-fns';
import {
  Shield, ShieldOff, ShieldCheck,
  Cpu, CircuitBoard, Fingerprint, Bug,
  AlertTriangle, CheckCircle, XCircle, Info,
} from 'lucide-react';
import { HardwareEvent, ThreatLevel, Severity } from '../types';
import { computeDmaBreakdown, scoreLabel, scoreColor, scoreBgColor, DmaScoreBreakdown } from '../utils/dmaScore';
import clsx from 'clsx';

interface Props {
  events: HardwareEvent[];
}

const THREAT_STYLE: Record<ThreatLevel, string> = {
  dangerous:  'bg-critical/10 text-critical border-critical/30',
  suspicious: 'bg-warning/10  text-warning  border-warning/30',
  safe:       'bg-info/10     text-info      border-info/30',
};

const HW_ICON: Record<string, typeof Cpu> = {
  PciDeviceScan:   Cpu,
  DmaDeviceFound:  CircuitBoard,
  FirmwareAnomaly: Bug,
  SignatureCheck:   Fingerprint,
  IommuStatus:     Shield,
};

export function HardwarePanel({ events }: Props) {
  const { iommu, pciScan, dmaDevices, signatures } = useMemo(() => {
    const iommu:      HardwareEvent[] = [];
    const pciScan:    HardwareEvent[] = [];
    const dmaDevices: HardwareEvent[] = [];
    const signatures: HardwareEvent[] = [];

    for (const ev of events) {
      switch (ev.hwType) {
        case 'IommuStatus':      iommu.push(ev);      break;
        case 'PciDeviceScan':    pciScan.push(ev);     break;
        case 'DmaDeviceFound':   dmaDevices.push(ev);  break;
        case 'SignatureCheck':   signatures.push(ev);  break;
      }
    }

    return { iommu, pciScan, dmaDevices, signatures };
  }, [events]);

  const breakdown = useMemo(() => computeDmaBreakdown(events), [events]);
  const flaggedSigs  = signatures.filter(e => e.flagged);
  const flaggedAll   = events.filter(e => e.flagged);
  const iommuOk = iommu.some(e => e.severity === 'info' && e.threat === 'safe');
  const hasDmaThreats = dmaDevices.length > 0;

  return (
    <div className="flex flex-col gap-4 h-full">
      {/* DMA Risk Score */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 shrink-0">
        <DmaScoreGauge breakdown={breakdown} />
        <div className="lg:col-span-2">
          <ScoreFactors breakdown={breakdown} />
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 shrink-0">
        <StatusCard
          icon={iommuOk ? ShieldCheck : ShieldOff}
          title="IOMMU / DMA Protection"
          ok={iommuOk}
          detail={iommu.length > 0 ? iommu[iommu.length - 1].detail : 'Scanning...'}
          severity={iommu.length > 0 ? iommu[iommu.length - 1].severity : 'info'}
        />
        <StatusCard
          icon={Cpu}
          title="PCI Bus Scan"
          ok={!hasDmaThreats}
          detail={pciScan.length > 0 ? pciScan[pciScan.length - 1].detail : 'Pending...'}
          severity={hasDmaThreats ? 'critical' : 'info'}
        />
        <StatusCard
          icon={CircuitBoard}
          title="DMA / FPGA Devices"
          ok={dmaDevices.length === 0}
          detail={hasDmaThreats ? `${dmaDevices.length} suspicious device(s)` : 'None detected'}
          severity={hasDmaThreats ? 'critical' : 'info'}
        />
        <StatusCard
          icon={Fingerprint}
          title="Signature Verification"
          ok={flaggedSigs.length === 0}
          detail={flaggedSigs.length > 0
            ? `${flaggedSigs.length} unsigned/invalid`
            : signatures.length > 0
              ? signatures[signatures.length - 1].detail
              : 'Scanning...'}
          severity={flaggedSigs.length > 0 ? 'warning' : 'info'}
        />
      </div>

      {/* Flagged Items Table */}
      {flaggedAll.length > 0 && (
        <div className="bg-surface border border-border rounded-lg flex-1 min-h-0 flex flex-col">
          <div className="px-4 py-3 border-b border-border shrink-0 flex items-center gap-2">
            <AlertTriangle size={14} className="text-warning" />
            <h3 className="text-xs uppercase tracking-widest text-muted font-mono">
              Flagged Items
            </h3>
            <span className="text-muted text-[10px] font-mono ml-auto">
              {flaggedAll.length} item{flaggedAll.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="overflow-auto flex-1 font-mono text-xs">
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-surface z-10">
                <tr className="text-muted uppercase text-[10px] tracking-wider">
                  <th className="px-3 py-2.5 text-left border-b border-border">Time</th>
                  <th className="px-3 py-2.5 text-left border-b border-border">Type</th>
                  <th className="px-3 py-2.5 text-left border-b border-border">Device</th>
                  <th className="px-3 py-2.5 text-left border-b border-border">Detail</th>
                  <th className="px-3 py-2.5 text-left border-b border-border">Vendor</th>
                  <th className="px-3 py-2.5 text-left border-b border-border">Threat</th>
                </tr>
              </thead>
              <tbody>
                {flaggedAll.map(ev => {
                  const Icon = HW_ICON[ev.hwType] ?? AlertTriangle;
                  return (
                    <tr
                      key={ev.id}
                      className={clsx(
                        'border-b border-border/30 transition-colors',
                        ev.threat === 'dangerous' ? 'bg-critical/[0.03]' :
                        ev.threat === 'suspicious' ? 'bg-warning/[0.03]' : '',
                      )}
                    >
                      <td className="px-3 py-2 text-muted whitespace-nowrap">
                        {format(new Date(ev.ts), 'HH:mm:ss')}
                      </td>
                      <td className="px-3 py-2">
                        <span className="flex items-center gap-1.5">
                          <Icon size={12} className="text-muted" />
                          <span className="text-text">{ev.hwType}</span>
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span className="text-text font-semibold">{ev.deviceName}</span>
                      </td>
                      <td className="px-3 py-2 text-muted max-w-xs truncate">{ev.detail}</td>
                      <td className="px-3 py-2 text-muted whitespace-nowrap">
                        {ev.vendorId > 0 ? (
                          <span className="text-[10px]">
                            0x{ev.vendorId.toString(16).toUpperCase().padStart(4, '0')}
                            :0x{ev.deviceId.toString(16).toUpperCase().padStart(4, '0')}
                          </span>
                        ) : (
                          <span className="text-border">--</span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <span className={clsx(
                          'px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider',
                          THREAT_STYLE[ev.threat],
                        )}>
                          {ev.threat}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {flaggedAll.length === 0 && (
        <div className="bg-surface border border-border rounded-lg flex-1 flex items-center justify-center">
          <div className="text-center">
            <ShieldCheck size={32} className="text-info mx-auto mb-2 opacity-50" />
            <p className="text-muted text-xs font-mono">No flagged hardware threats detected.</p>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── DMA Risk Score Gauge ───────────────────────────────────────── */

function DmaScoreGauge({ breakdown }: { breakdown: DmaScoreBreakdown }) {
  const { total } = breakdown;
  const label = scoreLabel(total);
  const color = scoreColor(total);
  const bg    = scoreBgColor(total);

  // SVG arc gauge
  const radius = 58;
  const stroke = 8;
  const circumference = Math.PI * radius; // half circle
  const progress = (total / 100) * circumference;

  return (
    <div className="bg-surface border border-border rounded-lg p-5 flex flex-col items-center justify-center">
      <h3 className="text-[10px] uppercase tracking-widest text-muted font-mono mb-3">
        DMA Risk Score
      </h3>

      <div className="relative w-36 h-20">
        <svg viewBox="0 0 140 80" className="w-full h-full">
          {/* Background arc */}
          <path
            d="M 10 75 A 58 58 0 0 1 130 75"
            fill="none"
            stroke="currentColor"
            strokeWidth={stroke}
            className="text-border"
            strokeLinecap="round"
          />
          {/* Progress arc */}
          <path
            d="M 10 75 A 58 58 0 0 1 130 75"
            fill="none"
            stroke="currentColor"
            strokeWidth={stroke}
            className={color}
            strokeLinecap="round"
            strokeDasharray={`${circumference}`}
            strokeDashoffset={`${circumference - progress}`}
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-0">
          <span className={clsx('text-3xl font-bold font-mono', color)}>{total}</span>
        </div>
      </div>

      <div className="flex items-center gap-2 mt-2">
        <span className={clsx('w-2 h-2 rounded-full', bg)} />
        <span className={clsx('text-xs font-mono font-semibold', color)}>{label}</span>
      </div>

      <div className="w-full mt-3 bg-border/30 rounded-full h-1.5 overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', bg)}
          style={{ width: `${total}%` }}
        />
      </div>

      <div className="flex justify-between w-full mt-1 text-[9px] text-muted font-mono">
        <span>0</span>
        <span>Safe</span>
        <span>Low</span>
        <span>Medium</span>
        <span>High</span>
        <span>100</span>
      </div>
    </div>
  );
}

/* ── Score Factor Breakdown ─────────────────────────────────────── */

function ScoreFactors({ breakdown }: { breakdown: DmaScoreBreakdown }) {
  const { factors, total } = breakdown;

  const SEV_ICON: Record<string, typeof AlertTriangle> = {
    critical: XCircle,
    warning:  AlertTriangle,
    info:     Info,
  };

  const SEV_COLOR: Record<string, string> = {
    critical: 'text-critical',
    warning:  'text-warning',
    info:     'text-info',
  };

  return (
    <div className="bg-surface border border-border rounded-lg p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[10px] uppercase tracking-widest text-muted font-mono">
          Score Breakdown
        </h3>
        <span className="text-muted text-[10px] font-mono">
          {factors.length} factor{factors.length !== 1 ? 's' : ''}
        </span>
      </div>

      {factors.length === 0 ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <CheckCircle size={20} className="text-info mx-auto mb-1.5 opacity-50" />
            <p className="text-muted text-[11px] font-mono">No risk factors detected</p>
          </div>
        </div>
      ) : (
        <div className="space-y-2 flex-1 overflow-auto">
          {factors.map((f, i) => {
            const Icon = SEV_ICON[f.severity] ?? Info;
            const pct = total > 0 ? (f.points / 100) * 100 : 0;

            return (
              <div key={i} className="group">
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={12} className={SEV_COLOR[f.severity]} />
                  <span className="text-text text-xs font-mono flex-1">{f.label}</span>
                  <span className={clsx('text-xs font-mono font-semibold', SEV_COLOR[f.severity])}>
                    +{f.points}
                  </span>
                </div>
                <div className="ml-5 bg-border/30 rounded-full h-1 overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-300',
                      f.severity === 'critical' ? 'bg-critical' :
                      f.severity === 'warning'  ? 'bg-warning'  : 'bg-info',
                    )}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ── Status Card ────────────────────────────────────────────────── */

function StatusCard({ icon: Icon, title, ok, detail, severity }: {
  icon: typeof Shield;
  title: string;
  ok: boolean;
  detail: string;
  severity: Severity;
}) {
  return (
    <div className={clsx(
      'bg-surface rounded-lg border p-3.5 transition-colors',
      ok ? 'border-border' : severity === 'critical'
        ? 'border-critical/40 bg-critical/[0.03]'
        : 'border-warning/40 bg-warning/[0.03]',
    )}>
      <div className="flex items-center gap-2.5 mb-2">
        <div className={clsx(
          'p-1.5 rounded',
          ok ? 'bg-info/10' : severity === 'critical' ? 'bg-critical/10' : 'bg-warning/10',
        )}>
          <Icon size={14} className={ok ? 'text-info' : severity === 'critical' ? 'text-critical' : 'text-warning'} />
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted font-mono leading-tight">{title}</span>
      </div>
      <div className="flex items-center gap-2 mb-1">
        {ok ? (
          <CheckCircle size={12} className="text-info" />
        ) : (
          <AlertTriangle size={12} className={severity === 'critical' ? 'text-critical' : 'text-warning'} />
        )}
        <span className={clsx(
          'text-xs font-mono font-semibold',
          ok ? 'text-info' : severity === 'critical' ? 'text-critical' : 'text-warning',
        )}>
          {ok ? 'OK' : 'ALERT'}
        </span>
      </div>
      <p className="text-muted text-[11px] font-mono truncate">{detail}</p>
    </div>
  );
}
