import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { format } from 'date-fns';
import { BarChart3 } from 'lucide-react';
import { ActivitySnapshot } from '../types';

interface Props {
  data: ActivitySnapshot[];
}

const COLORS = { critical: '#f85149', warning: '#d29922', info: '#3fb950' } as const;

export function ActivityChart({ data }: Props) {
  const formatted = data.map(d => ({ ...d, label: format(new Date(d.ts), 'HH:mm:ss') }));

  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <div className="flex items-center gap-2 mb-4">
        <BarChart3 size={14} className="text-muted" />
        <h2 className="text-xs uppercase tracking-widest text-muted font-mono">
          API Call Activity
        </h2>
        <span className="text-muted text-[10px] font-mono ml-auto">last 60 s</span>
      </div>

      {data.length === 0 ? (
        <div className="text-center py-8">
          <BarChart3 size={24} className="text-border mx-auto mb-2" />
          <p className="text-muted text-xs font-mono">Waiting for events...</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={formatted} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
            <defs>
              {(['critical', 'warning', 'info'] as const).map(k => (
                <linearGradient key={k} id={`grad-${k}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={COLORS[k]} stopOpacity={0.4} />
                  <stop offset="95%" stopColor={COLORS[k]} stopOpacity={0.02} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
            <XAxis dataKey="label" tick={{ fill: '#8b949e', fontSize: 10 }} />
            <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
            <Tooltip
              contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
              labelStyle={{ color: '#e6edf3', fontSize: 11 }}
              itemStyle={{ fontSize: 11 }}
            />
            <Legend wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
            {(['critical', 'warning', 'info'] as const).map(k => (
              <Area
                key={k}
                type="monotone"
                dataKey={k}
                stroke={COLORS[k]}
                fill={`url(#grad-${k})`}
                strokeWidth={1.5}
                dot={false}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
