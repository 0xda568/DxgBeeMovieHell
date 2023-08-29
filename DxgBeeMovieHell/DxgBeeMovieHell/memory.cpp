#include "memory.h"
#include "def.h"

#include <cstdint>

bool WriteToROMem(void* address, void* buffer, size_t size)
{
	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl)
		return false;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	RtlCopyMemory(Mapping, buffer, size);
	
	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

UNICODE_STRING GetProcessNameByPID(HANDLE pHandle) {

	ULONG len = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);

	PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, 0x44415348);

	if (!pProcessInfo)
		return RTL_CONSTANT_STRING(L"");

	PVOID poolBeginning = pProcessInfo;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, pProcessInfo, len, &len);

	if (status < 0 || status > 0)
		return RTL_CONSTANT_STRING(L"");

	PUNICODE_STRING result = 0;

	for (int i = 0; i < 6000; i++) {
		if (pProcessInfo->UniqueProcessId == pHandle) {
			break;
		}
		if (!pProcessInfo->NextEntryOffset)
			break;
		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)pProcessInfo + pProcessInfo->NextEntryOffset);
	}

	if (pProcessInfo)
		ExFreePoolWithTag(poolBeginning, 0x44415348);

	return pProcessInfo->ImageName;
}

// really unsafe function, my cause one or the other bluescreen
HANDLE GetProcessHandle(PUNICODE_STRING processName) {

	ULONG len = 0;
	ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);

	PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, len, 0x44415348);

	if (!pProcessInfo)
		return 0;

	PVOID poolBeginning = pProcessInfo;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, pProcessInfo, len, &len);

	if (status < 0 || status > 0) {
		ExFreePoolWithTag(poolBeginning, 0x44415348);
		return 0;
	}

	while (1) {

		if (!RtlCompareUnicodeString(&(pProcessInfo->ImageName), processName, TRUE)) {
			break;
			//ObsPrint("process %wZ, running with PID %d", &(pProcessInfo->ImageName), pProcessInfo->UniqueProcessId);
		}
		if (!pProcessInfo->NextEntryOffset)
			break;

		pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((unsigned char*)pProcessInfo + pProcessInfo->NextEntryOffset);
	}

	if (pProcessInfo)
		ExFreePoolWithTag(poolBeginning, 0x44415348);

	return pProcessInfo->UniqueProcessId;
}

PVOID GetSystemModuleBaseAddress(const char* moduleName) {

	ULONG len = 0;
	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

	if (!len)
		return 0;

	PRTL_PROCESS_MODULES pModuleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, len, 0x44415348);

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, len, &len);

	if (!NT_SUCCESS(status))
		return 0;

	PRTL_PROCESS_MODULE_INFORMATION module = pModuleInfo->Modules;

	PVOID moduleAddress = 0;

	for (ULONG i = 0; i < pModuleInfo->NumberOfModules; i++) {
		//ObsPrint("%s found at 0x%llx", (wchar_t*)module[i].FullPathName, module[i].ImageBase);

		//ObsPrint("%s | %s", (char*)module[i].FullPathName, moduleName);
		if (!_stricmp((char*)module[i].FullPathName, moduleName)) {
			moduleAddress = module[i].ImageBase;
			//ObsPrint("win32kfull found at 0x%llx", module[i].ImageBase);
			break;
		}
	}

	if (pModuleInfo)
		ExFreePoolWithTag(pModuleInfo, 0x44415348);

	if (moduleAddress <= 0)
		return 0;

	return moduleAddress;
}