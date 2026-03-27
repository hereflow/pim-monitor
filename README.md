# Process Integrity Monitor

Intercepta APIs de memória do Windows em dois níveis (kernel32 + ntdll) e exibe os eventos num dashboard web em tempo real.

```
monitor.exe ─ pipe >> NestJS - ws >> React
monitor-driver.sys (ObCallbacks + ProcessNotify)
```

## Stack

| | |
|---|---|
| C++ monitor | MinHook, Named Pipe, SyscallMap (SSN resolver) |
| Kernel driver | WDM, ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx |
| Backend | NestJS 10, Socket.IO, DDD |
| Frontend | React 18, Vite, Tailwind, Recharts |

## Rodar

```bash
# backend
cd backend && pnpm install && pnpm start:dev

# frontend
cd frontend && pnpm install && pnpm dev
```

```powershell
# monitor — abra monitor-core/monitor.sln no Visual Studio
# vcpkg install minhook:x64-windows && vcpkg integrate install
# build Release x64, depois:
.\monitor-core\build\Release\monitor.exe --self
```

```powershell
# driver — requer WDK
# abra monitor-driver/monitor-driver.vcxproj, compile Release x64
bcdedit /set testsigning on
sc create ProcMonitor type= kernel binPath= "C:\caminho\monitor-driver.sys"
sc start ProcMonitor
```

## O que captura

**kernel32 + ntdll (dois níveis de hook):**
- `OpenProcess` / `NtOpenProcess`
- `ReadProcessMemory` / `NtReadVirtualMemory`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `VirtualAllocEx` / `NtAllocateVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`

**Kernel:**
- Abertura de handles (`ObRegisterCallbacks`)
- Criação/término de processos (`PsSetCreateProcessNotifyRoutineEx`)

**Detecção de bypass:**
- SSNs resolvidos dinamicamente da ntdll — detecta discrepâncias de syscall direto
- Chamadas de regiões sem backing em disco são marcadas como suspeitas

---

> Somente para pesquisa defensiva e uso educacional.
