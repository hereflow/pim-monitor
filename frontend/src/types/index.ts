export type Severity = 'info' | 'warning' | 'critical';

export type ApiName =
  | 'OpenProcess'
  | 'ReadProcessMemory'
  | 'WriteProcessMemory'
  | 'VirtualAllocEx'
  | 'CreateRemoteThread'
  | 'NtOpenProcess'
  | 'NtReadVirtualMemory'
  | 'NtWriteVirtualMemory'
  | 'NtAllocateVirtualMemory'
  | 'NtCreateThreadEx';

export interface ProcessEvent {
  id: number;
  ts: number;
  api: ApiName;
  severity: Severity;
  origin?: string;
  suspiciousCaller?: boolean;
  callerPid: number;
  callerName: string;
  targetPid: number;
  targetName: string;
  param1: number;
  param2: number;
  param3: number;
  returnValue: number;
  success: boolean;
}

export interface ActivitySnapshot {
  ts: number;
  info: number;
  warning: number;
  critical: number;
  total: number;
}

export interface Stats {
  total: number;
  critical: number;
  warning: number;
  info: number;
  uniqueCallers: number;
  uniqueTargets: number;
}

export type HwEventType =
  | 'PciDeviceScan'
  | 'DmaDeviceFound'
  | 'FirmwareAnomaly'
  | 'SignatureCheck'
  | 'IommuStatus';

export type ThreatLevel = 'safe' | 'suspicious' | 'dangerous';

export interface HardwareEvent {
  id: number;
  ts: number;
  hwType: HwEventType;
  severity: Severity;
  threat: ThreatLevel;
  deviceName: string;
  detail: string;
  vendorId: number;
  deviceId: number;
  subVendorId: number;
  subDeviceId: number;
  location: string;
  flagged: boolean;
}
