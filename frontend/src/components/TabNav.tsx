import { LayoutDashboard, List, Shield } from 'lucide-react';
import { HardwareEvent } from '../types';
import { computeDmaScore } from '../utils/dmaScore';
import clsx from 'clsx';
import type { Tab } from '../App';

interface Props {
  active: Tab;
  onChange: (tab: Tab) => void;
  hwEvents: HardwareEvent[];
}

const TABS: { id: Tab; label: string; icon: typeof LayoutDashboard }[] = [
  { id: 'overview',  label: 'Overview',           icon: LayoutDashboard },
  { id: 'events',    label: 'Event Log',          icon: List },
  { id: 'hardware',  label: 'Hardware Security',  icon: Shield },
];

export function TabNav({ active, onChange, hwEvents }: Props) {
  const score = computeDmaScore(hwEvents);

  return (
    <nav className="flex items-center gap-1 px-4 pt-2 pb-0 bg-bg border-b border-border">
      {TABS.map(t => {
        const Icon = t.icon;
        const isActive = active === t.id;

        return (
          <button
            key={t.id}
            onClick={() => onChange(t.id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2.5 text-xs font-mono rounded-t transition-colors border-b-2',
              isActive
                ? 'text-accent border-accent bg-surface'
                : 'text-muted border-transparent hover:text-text hover:bg-surface/50',
            )}
          >
            <Icon size={14} />
            {t.label}

            {t.id === 'hardware' && score > 0 && (
              <span className={clsx(
                'ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold',
                score >= 60 ? 'bg-critical/20 text-critical'
                  : score >= 30 ? 'bg-warning/20 text-warning'
                  : 'bg-info/20 text-info',
              )}>
                {score}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
