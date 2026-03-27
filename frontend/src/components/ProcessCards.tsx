import { useMemo } from 'react';
import { Target, ShieldAlert, AlertTriangle, Activity } from 'lucide-react';
import { ProcessEvent } from '../types';
import clsx from 'clsx';

interface Props {
  events: ProcessEvent[];
}

interface ProcessSummary {
  name: string;
  pid: number;
  total: number;
  critical: number;
  warning: number;
  apis: Set<string>;
}

export function ProcessCards({ events }: Props) {
  const processes = useMemo<ProcessSummary[]>(() => {
    const map = new Map<number, ProcessSummary>();

    for (const ev of events) {
      const entry = map.get(ev.targetPid) ?? {
        name: ev.targetName,
        pid: ev.targetPid,
        total: 0,
        critical: 0,
        warning: 0,
        apis: new Set<string>(),
      };
      entry.total++;
      if (ev.severity === 'critical') entry.critical++;
      if (ev.severity === 'warning')  entry.warning++;
      entry.apis.add(ev.api);
      map.set(ev.targetPid, entry);
    }

    return Array.from(map.values()).sort((a, b) => b.critical - a.critical || b.total - a.total);
  }, [events]);

  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-3">
        <Target size={14} className="text-muted" />
        <h2 className="text-xs uppercase tracking-widest text-muted font-mono">
          Monitored Targets
        </h2>
        {processes.length > 0 && (
          <span className="text-muted text-[10px] font-mono ml-auto">
            {processes.length} process{processes.length !== 1 ? 'es' : ''}
          </span>
        )}
      </div>

      {processes.length === 0 ? (
        <div className="text-center py-8">
          <Target size={24} className="text-border mx-auto mb-2" />
          <p className="text-muted text-xs font-mono">No targets observed yet.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
          {processes.map(p => (
            <div
              key={p.pid}
              className={clsx(
                'rounded-lg border p-3 transition-colors',
                p.critical > 0 ? 'border-critical/40 bg-critical/[0.03]' :
                p.warning  > 0 ? 'border-warning/40  bg-warning/[0.03]'  :
                                  'border-border bg-bg',
              )}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <div className={clsx(
                    'p-1 rounded shrink-0',
                    p.critical > 0 ? 'bg-critical/10' :
                    p.warning  > 0 ? 'bg-warning/10'  : 'bg-border/30',
                  )}>
                    {p.critical > 0 ? (
                      <ShieldAlert size={12} className="text-critical" />
                    ) : p.warning > 0 ? (
                      <AlertTriangle size={12} className="text-warning" />
                    ) : (
                      <Activity size={12} className="text-muted" />
                    )}
                  </div>
                  <span className="text-text text-xs font-mono font-semibold truncate">{p.name}</span>
                </div>
                <span className="text-muted text-[10px] font-mono shrink-0 border border-border rounded px-1.5 py-0.5">
                  {p.pid}
                </span>
              </div>

              <div className="flex gap-3 text-[11px] font-mono mb-2">
                {p.critical > 0 && (
                  <span className="flex items-center gap-1 text-critical">
                    <span className="w-1.5 h-1.5 rounded-full bg-critical" />
                    {p.critical} critical
                  </span>
                )}
                {p.warning > 0 && (
                  <span className="flex items-center gap-1 text-warning">
                    <span className="w-1.5 h-1.5 rounded-full bg-warning" />
                    {p.warning} warning
                  </span>
                )}
                <span className="text-muted">{p.total} total</span>
              </div>

              <div className="flex flex-wrap gap-1">
                {Array.from(p.apis).map(api => (
                  <span key={api} className="px-1.5 py-0.5 bg-bg border border-border text-muted text-[10px] font-mono rounded">
                    {api}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
