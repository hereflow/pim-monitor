import { Trash2, Wifi, WifiOff, Loader } from 'lucide-react';
import { ConnectionStatus } from '../hooks/useMonitor';
import { Stats } from '../types';

interface Props {
  status: ConnectionStatus;
  stats: Stats | null;
  onClear: () => void;
}

const STATUS_ICON: Record<ConnectionStatus, typeof Wifi> = {
  connected:    Wifi,
  disconnected: WifiOff,
  connecting:   Loader,
};

const STATUS_COLOR: Record<ConnectionStatus, string> = {
  connected:    'text-info',
  disconnected: 'text-critical',
  connecting:   'text-warning animate-spin',
};

const STATUS_LABEL: Record<ConnectionStatus, string> = {
  connected:    'Connected',
  disconnected: 'Disconnected',
  connecting:   'Connecting',
};

export function StatusBar({ status, stats, onClear }: Props) {
  const Icon = STATUS_ICON[status];

  return (
    <header className="flex items-center justify-between px-5 py-3 bg-surface border-b border-border select-none shrink-0">
      <div className="flex items-center gap-3">
        <span className="text-text font-semibold text-sm tracking-widest uppercase">
          Process Integrity Monitor
        </span>
        <span className="text-muted text-[10px] border border-border rounded px-1.5 py-0.5">v1.0</span>
      </div>

      <div className="flex items-center gap-5 text-xs font-mono">
        {stats && (
          <>
            <StatItem label="Events"   value={stats.total} />
            <StatItem label="Critical" value={stats.critical} color="text-critical" />
            <StatItem label="Warning"  value={stats.warning}  color="text-warning" />
            <StatItem label="Targets"  value={stats.uniqueTargets} />
          </>
        )}

        <button
          onClick={onClear}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-muted hover:text-critical hover:border-critical/50 transition-colors"
        >
          <Trash2 size={12} />
          Clear
        </button>

        <div className="flex items-center gap-2 pl-3 border-l border-border">
          <Icon size={14} className={STATUS_COLOR[status]} />
          <span className="text-muted">{STATUS_LABEL[status]}</span>
        </div>
      </div>
    </header>
  );
}

function StatItem({ label, value, color = 'text-text' }: { label: string; value: number; color?: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="text-muted">{label}</span>
      <span className={`font-semibold ${color}`}>{value.toLocaleString()}</span>
    </span>
  );
}
