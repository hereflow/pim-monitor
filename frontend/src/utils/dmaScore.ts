import { HardwareEvent } from '../types';

export interface DmaScoreBreakdown {
  total: number;
  iommuDisabled: boolean;
  noDmarTable: boolean;
  fpgaDevices: number;
  knownDmaDevices: number;
  unsignedProcesses: number;
  firmwareAnomalies: number;
  factors: { label: string; points: number; severity: 'critical' | 'warning' | 'info' }[];
}

export function computeDmaScore(events: HardwareEvent[]): number {
  return computeDmaBreakdown(events).total;
}

export function computeDmaBreakdown(events: HardwareEvent[]): DmaScoreBreakdown {
  const factors: DmaScoreBreakdown['factors'] = [];
  let total = 0;

  const iommuEvents = events.filter(e => e.hwType === 'IommuStatus');
  const iommuDisabled = iommuEvents.some(e => e.severity === 'critical');
  const noDmarTable = iommuEvents.some(e =>
    e.severity === 'warning' && e.deviceName === 'ACPI');

  if (iommuDisabled) {
    factors.push({ label: 'IOMMU / DMA Protection disabled', points: 40, severity: 'critical' });
    total += 40;
  }

  if (noDmarTable) {
    factors.push({ label: 'No DMAR/IVRS ACPI table found', points: 15, severity: 'warning' });
    total += 15;
  }

  const dmaDevices = events.filter(e => e.hwType === 'DmaDeviceFound');
  const knownDma = dmaDevices.filter(e => e.threat === 'dangerous');
  const fpgaSuspicious = dmaDevices.filter(e => e.threat === 'suspicious');

  if (knownDma.length > 0) {
    const pts = Math.min(knownDma.length * 50, 50);
    factors.push({
      label: `${knownDma.length} known DMA device(s) detected`,
      points: pts,
      severity: 'critical',
    });
    total += pts;
  }

  if (fpgaSuspicious.length > 0) {
    const pts = Math.min(fpgaSuspicious.length * 25, 30);
    factors.push({
      label: `${fpgaSuspicious.length} FPGA vendor device(s) on PCI bus`,
      points: pts,
      severity: 'warning',
    });
    total += pts;
  }

  const sigs = events.filter(e => e.hwType === 'SignatureCheck' && e.flagged);
  if (sigs.length > 0) {
    const pts = Math.min(sigs.length * 3, 15);
    factors.push({
      label: `${sigs.length} unsigned/invalid process signature(s)`,
      points: pts,
      severity: 'warning',
    });
    total += pts;
  }

  const firmware = events.filter(e => e.hwType === 'FirmwareAnomaly');
  if (firmware.length > 0) {
    factors.push({
      label: `${firmware.length} firmware anomaly(ies)`,
      points: 25,
      severity: 'critical',
    });
    total += 25;
  }

  return {
    total: Math.min(total, 100),
    iommuDisabled,
    noDmarTable,
    fpgaDevices: fpgaSuspicious.length,
    knownDmaDevices: knownDma.length,
    unsignedProcesses: sigs.length,
    firmwareAnomalies: firmware.length,
    factors,
  };
}

export function scoreLabel(score: number): string {
  if (score <= 10) return 'Safe';
  if (score <= 30) return 'Low Risk';
  if (score <= 60) return 'Medium Risk';
  if (score <= 80) return 'High Risk';
  return 'Critical';
}

export function scoreColor(score: number): string {
  if (score <= 10) return 'text-info';
  if (score <= 30) return 'text-info';
  if (score <= 60) return 'text-warning';
  return 'text-critical';
}

export function scoreBgColor(score: number): string {
  if (score <= 10) return 'bg-info';
  if (score <= 30) return 'bg-info';
  if (score <= 60) return 'bg-warning';
  return 'bg-critical';
}
