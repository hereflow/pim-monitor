export type Severity   = 'info' | 'warning' | 'critical';
export type CallOrigin = 'api' | 'nt' | 'direct';
export type ApiName    =
  | 'OpenProcess' | 'ReadProcessMemory' | 'WriteProcessMemory'
  | 'VirtualAllocEx' | 'CreateRemoteThread'
  | 'NtOpenProcess' | 'NtReadVirtualMemory' | 'NtWriteVirtualMemory'
  | 'NtAllocateVirtualMemory' | 'NtCreateThreadEx';

export interface ProcessEvent {
  readonly type?: 'process';
  readonly id: number;
  readonly ts: number;
  readonly api: ApiName;
  readonly severity: Severity;
  readonly origin: CallOrigin;
  readonly suspiciousCaller: boolean;
  readonly callerPid: number;
  readonly callerName: string;
  readonly targetPid: number;
  readonly targetName: string;
  readonly param1: number;
  readonly param2: number;
  readonly param3: number;
  readonly returnValue: number;
  readonly success: boolean;
}

export interface ActivityBucket {
  readonly ts: number;
  info: number;
  warning: number;
  critical: number;
  total: number;
}
