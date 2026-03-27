import { useState, useMemo, useRef, useEffect } from 'react';
import { format } from 'date-fns';
import { CheckCircle, XCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { ProcessEvent, Severity, ApiName } from '../types';
import clsx from 'clsx';

interface Props {
  events: ProcessEvent[];
}

const SEV_STYLE: Record<Severity, string> = {
  critical: 'bg-critical/15 text-critical border-critical/30',
  warning:  'bg-warning/15  text-warning  border-warning/30',
  info:     'bg-info/15     text-info      border-info/30',
};

const ROW_BG: Record<Severity, string> = {
  critical: 'bg-critical/[0.03]',
  warning:  'bg-warning/[0.03]',
  info:     '',
};

const API_COLOR: Record<string, string> = {
  OpenProcess:            'text-accent',
  ReadProcessMemory:      'text-yellow-400',
  WriteProcessMemory:     'text-critical',
  VirtualAllocEx:         'text-orange-400',
  CreateRemoteThread:     'text-pink-400',
  NtOpenProcess:          'text-accent',
  NtReadVirtualMemory:    'text-yellow-400',
  NtWriteVirtualMemory:   'text-critical',
  NtAllocateVirtualMemory:'text-orange-400',
  NtCreateThreadEx:       'text-pink-400',
};

const ALL_APIS: ApiName[] = [
  'OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory',
  'VirtualAllocEx', 'CreateRemoteThread',
  'NtOpenProcess', 'NtReadVirtualMemory', 'NtWriteVirtualMemory',
  'NtAllocateVirtualMemory', 'NtCreateThreadEx',
];

const ALL_SEVERITIES: Severity[] = ['info', 'warning', 'critical'];

export function EventLog({ events }: Props) {
  const [filterApi,      setFilterApi]      = useState<ApiName | 'all'>('all');
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');
  const [search,         setSearch]         = useState('');
  const [autoScroll,     setAutoScroll]     = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => events.filter(ev => {
    if (filterApi      !== 'all' && ev.api      !== filterApi)      return false;
    if (filterSeverity !== 'all' && ev.severity !== filterSeverity) return false;
    if (search) {
      const q = search.toLowerCase();
      return ev.callerName.toLowerCase().includes(q) ||
             ev.targetName.toLowerCase().includes(q) ||
             String(ev.callerPid).includes(q) ||
             String(ev.targetPid).includes(q);
    }
    return true;
  }), [events, filterApi, filterSeverity, search]);

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [filtered, autoScroll]);

  return (
    <div className="bg-surface border border-border rounded-lg flex flex-col h-full">
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-border shrink-0">
        <h2 className="text-xs uppercase tracking-widest text-muted font-mono mr-2">Event Log</h2>
        <input
          type="text"
          placeholder="Search process..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-bg border border-border rounded px-2.5 py-1.5 text-xs text-text font-mono placeholder-muted focus:outline-none focus:border-accent w-44"
        />
        <Select
          value={filterApi}
          onChange={v => setFilterApi(v as ApiName | 'all')}
          options={[{ value: 'all', label: 'All APIs' }, ...ALL_APIS.map(a => ({ value: a, label: a }))]}
        />
        <Select
          value={filterSeverity}
          onChange={v => setFilterSeverity(v as Severity | 'all')}
          options={[{ value: 'all', label: 'All Severity' }, ...ALL_SEVERITIES.map(s => ({ value: s, label: s }))]}
        />
        <span className="text-muted text-xs font-mono ml-auto">{filtered.length.toLocaleString()} events</span>
        <label className="flex items-center gap-1.5 text-xs text-muted cursor-pointer select-none">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-accent" />
          Auto-scroll
        </label>
      </div>

      <div className="overflow-auto flex-1 font-mono text-xs">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-surface z-10">
            <tr className="text-muted uppercase text-[10px] tracking-wider">
              <Th>Time</Th><Th>Severity</Th><Th>API</Th>
              <Th>Caller</Th><Th>Target</Th><Th>Param1</Th><Th>Result</Th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="text-center text-muted py-12">No events match the current filter.</td></tr>
            ) : (
              filtered.map(ev => <EventRow key={ev.id} ev={ev} />)
            )}
          </tbody>
        </table>
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function EventRow({ ev }: { ev: ProcessEvent }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <tr
        onClick={() => setExpanded(x => !x)}
        className={clsx(
          'border-b border-border/30 cursor-pointer hover:bg-white/[0.02] transition-colors',
          ROW_BG[ev.severity],
        )}
      >
        <Td className="text-muted whitespace-nowrap">
          <span className="flex items-center gap-1.5">
            {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
            {format(new Date(ev.ts), 'HH:mm:ss.SSS')}
          </span>
        </Td>
        <Td>
          <span className={clsx('px-2 py-0.5 rounded border text-[10px] uppercase tracking-wider', SEV_STYLE[ev.severity])}>
            {ev.severity}
          </span>
        </Td>
        <Td className={API_COLOR[ev.api] ?? 'text-text'}>{ev.api}</Td>
        <Td>
          <span className="text-text">{ev.callerName}</span>
          <span className="text-muted ml-1">({ev.callerPid})</span>
        </Td>
        <Td>
          <span className="text-text">{ev.targetName}</span>
          <span className="text-muted ml-1">({ev.targetPid})</span>
        </Td>
        <Td className="text-muted">0x{ev.param1.toString(16).toUpperCase()}</Td>
        <Td>
          {ev.success
            ? <CheckCircle size={14} className="text-info" />
            : <XCircle     size={14} className="text-critical" />}
        </Td>
      </tr>

      {expanded && (
        <tr className="bg-bg border-b border-border/30">
          <td colSpan={7} className="px-6 py-3">
            <pre className="text-muted text-[11px] whitespace-pre-wrap">
{JSON.stringify({
  id: ev.id, api: ev.api, origin: ev.origin,
  suspiciousCaller: ev.suspiciousCaller,
  param1: `0x${ev.param1.toString(16).toUpperCase()}`,
  param2: `0x${ev.param2.toString(16).toUpperCase()}`,
  param3: ev.param3,
  returnValue: `0x${ev.returnValue.toString(16).toUpperCase()}`,
  success: ev.success,
}, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2.5 text-left border-b border-border">{children}</th>;
}

function Td({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={clsx('px-3 py-2', className)}>{children}</td>;
}

function Select({ value, onChange, options }: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="bg-bg border border-border rounded px-2.5 py-1.5 text-xs text-text font-mono focus:outline-none focus:border-accent"
    >
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}
