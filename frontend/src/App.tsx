import { useState }         from 'react';
import { useMonitor }       from './hooks/useMonitor';
import { StatusBar }        from './components/StatusBar';
import { TabNav }           from './components/TabNav';
import { OverviewTab }      from './components/OverviewTab';
import { EventLog }         from './components/EventLog';
import { HardwarePanel }    from './components/HardwarePanel';

export type Tab = 'overview' | 'events' | 'hardware';

export default function App() {
  const { events, hwEvents, activity, stats, status, clearEvents } = useMonitor();
  const [tab, setTab] = useState<Tab>('overview');

  return (
    <div className="h-screen bg-bg text-text flex flex-col font-mono overflow-hidden">
      <StatusBar status={status} stats={stats} onClear={clearEvents} />
      <TabNav active={tab} onChange={setTab} hwEvents={hwEvents} />

      <main className="flex-1 min-h-0 overflow-auto p-4">
        {tab === 'overview'  && <OverviewTab events={events} hwEvents={hwEvents} activity={activity} stats={stats} />}
        {tab === 'events'    && <EventLog events={events} />}
        {tab === 'hardware'  && <HardwarePanel events={hwEvents} />}
      </main>
    </div>
  );
}
