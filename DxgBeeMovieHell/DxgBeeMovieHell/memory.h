#pragma once

#include "def.h"
#include <ntifs.h>

bool WriteToROMem(void* address, void* buffer, size_t size);

ULONGLONG GetW32pServiceTableFunc(ULONGLONG W32pServiceTable, int syscall);

UNICODE_STRING GetProcessNameByPID(HANDLE pHandle);

HANDLE GetProcessHandle(PUNICODE_STRING processName);

PVOID GetSystemModuleBaseAddress(const char* moduleName);

inline DWORD RvaToOffset(unsigned char* pe, DWORD Rva) {

	WORD numberOfSections = *(WORD*)(pe + 6);

	WORD sizeOfOptHeader = *(WORD*)(pe + 20);

	unsigned char* sectionHeader = (pe + sizeOfOptHeader + 24);

	PIMAGE_SECTION_HEADER sec = 0;

	for (int i = 0; i < numberOfSections; i++) {
		sec = (PIMAGE_SECTION_HEADER)(sectionHeader + (40 * i));
		if (sec->VirtualAddress <= Rva) {
			if ((sec->VirtualAddress + sec->Misc.VirtualSize) > Rva) {

				Rva -= sec->VirtualAddress;
				Rva += sec->PointerToRawData;

				return Rva;
			}
		}
	}
	return -1;
}

inline ULONGLONG GetW32pServiceTableFunc(ULONGLONG W32pServiceTable, int syscall) {

	ULONGLONG qwTemp = 0;
	LONG dwTemp = 0;

	qwTemp = W32pServiceTable + 4 * (syscall - 0x1000);
	dwTemp = *(PLONG)qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + (LONG64)dwTemp;

	return qwTemp;
}