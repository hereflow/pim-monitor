export type HwEventType =
  | 'PciDeviceScan'
  | 'DmaDeviceFound'
  | 'FirmwareAnomaly'
  | 'SignatureCheck'
  | 'IommuStatus';

export type ThreatLevel = 'safe' | 'suspicious' | 'dangerous';

export type Severity = 'info' | 'warning' | 'critical';

export interface HardwareEvent {
  readonly id: number;
  readonly ts: number;
  readonly hwType: HwEventType;
  readonly severity: Severity;
  readonly threat: ThreatLevel;
  readonly deviceName: string;
  readonly detail: string;
  readonly vendorId: number;
  readonly deviceId: number;
  readonly subVendorId: number;
  readonly subDeviceId: number;
  readonly location: string;
  readonly flagged: boolean;
}
