import { AlertTriangle, ShieldAlert, Activity, Users } from 'lucide-react';
import { ActivityChart }  from './ActivityChart';
import { ProcessCards }   from './ProcessCards';
import { AlertBanner }    from './AlertBanner';
import { ProcessEvent, HardwareEvent, ActivitySnapshot, Stats } from '../types';

interface Props {
  events: ProcessEvent[];
  hwEvents: HardwareEvent[];
  activity: ActivitySnapshot[];
  stats: Stats | null;
}

export function OverviewTab({ events, hwEvents, activity, stats }: Props) {
  return (
    <div className="flex flex-col gap-4 h-full">
      <AlertBanner events={events} hwEvents={hwEvents} />

      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 shrink-0">
          <MetricCard icon={Activity}      label="Total Events"   value={stats.total}          color="text-accent"   bg="bg-accent/10"   border="border-accent/20" />
          <MetricCard icon={ShieldAlert}   label="Critical"       value={stats.critical}       color="text-critical" bg="bg-critical/10" border="border-critical/20" />
          <MetricCard icon={AlertTriangle} label="Warning"        value={stats.warning}        color="text-warning"  bg="bg-warning/10"  border="border-warning/20" />
          <MetricCard icon={Users}         label="Unique Targets" value={stats.uniqueTargets}  color="text-info"     bg="bg-info/10"     border="border-info/20" />
        </div>
      )}

      <div className="shrink-0">
        <ActivityChart data={activity} />
      </div>

      <div className="flex-1 min-h-0 overflow-auto">
        <ProcessCards events={events} />
      </div>
    </div>
  );
}

function MetricCard({ icon: Icon, label, value, color, bg, border }: {
  icon: typeof Activity;
  label: string;
  value: number;
  color: string;
  bg: string;
  border: string;
}) {
  return (
    <div className={`rounded-lg border ${border} ${bg} p-4 flex items-center gap-3`}>
      <div className={`p-2 rounded ${bg}`}>
        <Icon size={18} className={color} />
      </div>
      <div>
        <div className="text-muted text-[10px] uppercase tracking-wider font-mono">{label}</div>
        <div className={`text-xl font-semibold font-mono ${color}`}>{value.toLocaleString()}</div>
      </div>
    </div>
  );
}
