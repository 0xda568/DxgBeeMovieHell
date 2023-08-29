#include "entry.h"
#include "memory.h"
#include "def.h"

#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include <wingdi.h>
#include <d3dkmthk.h>
#include <intrin.h>

typedef DWORD LFTYPE;

typedef BOOL(__stdcall* MONITORENUMPROC)(HMONITOR, HDC, LPRECT, LPARAM);

ULONGLONG orig = 0;
HDC(*NtUserGetDC)(HWND hWnd) = 0;
BOOL(*NtGdiPatBlt)(HDC hdc, int x, int y, int w, int h, DWORD rop) = 0;
void(*GreExtTextOutW)(std::uint64_t dc, std::uint32_t left, std::uint32_t top, std::uint64_t, std::uint64_t,LPCWSTR text, std::uint32_t textSize, std::uint64_t, std::uint64_t, std::uint64_t);
int(*GreGetDeviceCaps)(HDC hdc, int index) = 0;

HBRUSH brush = 0;
HFONT def = 0;
ULONG timeSec;
LARGE_INTEGER SystemTime;

int64_t ret = 0;

PUCHAR secondSubmitCommand = 0;

int width = -1;
int height = -1;

HDC mainHDC = 0;

int beeIndex = 0;

int64_t hookFunc(D3DKMT_SUBMITCOMMAND* data) {

	if(mainHDC == 0)
		mainHDC = NtUserGetDC(0x00);

	if(width == -1)
		width = GreGetDeviceCaps(mainHDC, HORZRES);
	
	if(height == -1)
		height = GreGetDeviceCaps(mainHDC, VERTRES);

	NtGdiPatBlt(mainHDC, 0, 0, width, height, PATCOPY);

	if ((beeIndex + 1) < (sizeof(beeMovie) / sizeof(beeMovie[0]))) {
		beeIndex++;
		int tmp = beeIndex % (height / 30);
		for(int i = 0; i <= tmp; i++)
			GreExtTextOutW((uint64_t)mainHDC, 0, 30 * i, 0, 0, beeMovie[beeIndex-tmp+i], wcslen(beeMovie[beeIndex-tmp+i]), 0, 0, 0);
	}

	return ((int64_t(__fastcall*)(D3DKMT_SUBMITCOMMAND * data))(PVOID)orig)(data);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, UNICODE_STRING regPath) {

	UNREFERENCED_PARAMETER(regPath);

	unsigned char* ntoskrnl = (unsigned char*)GetSystemModuleBaseAddress("\\SystemRoot\\System32\\ntoskrnl.exe");

	unsigned char* pe = (unsigned char*)ntoskrnl + *(LONG*)((unsigned char*)(ntoskrnl)+0x3C);

	WORD numberOfSections = *(WORD*)(pe + 6);
	WORD sizeOfOptHeader = *(WORD*)(pe + 20);

	unsigned char* sectionHeader = (pe + sizeOfOptHeader + 24);

	unsigned char* textSection = 0;

	for (int i = 0; i < numberOfSections; i++) {
		if (!strncmp((char*)(sectionHeader + (40 * i)), ".text", 5))
			textSection = sectionHeader + (40 * i);
	}

	const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

	PIMAGE_SECTION_HEADER textSec = (PIMAGE_SECTION_HEADER)textSection;

	ULONG_PTR addressAfterPattern = 0;

	for (int i = 0; i < textSec->Misc.VirtualSize; i++) {
		if (RtlCompareMemory((unsigned char*)ntoskrnl + (textSec->VirtualAddress) + i, KiSystemServiceStartPattern, sizeof(KiSystemServiceStartPattern)) == sizeof KiSystemServiceStartPattern) {
			addressAfterPattern = (ULONG_PTR)(ntoskrnl + (textSec->VirtualAddress) + i + sizeof KiSystemServiceStartPattern);
			//KiSystemServiceStartAddr = (unsigned char*)ntoskrnl + (textSec->VirtualAddress) + i;
			//ObsPrint("found");
			break;
		}
	}

	unsigned char* addressAfterPatternChar = (unsigned char*)addressAfterPattern;

	struct SSDTStruct
	{
		LONG* pServiceTable;
		PVOID pCounterTable;
#ifdef _WIN64
		ULONGLONG NumberOfServices;
#else
		ULONG NumberOfServices;
#endif
		PCHAR pArgumentTable;
	};

	typedef struct tag_SYSTEM_SERVICE_TABLE {
		PULONG      ServiceTable;
		PULONG_PTR  CounterTable;
		ULONG_PTR   ServiceLimit;
		PBYTE       ArgumentTable;
	} SYSTEM_SERVICE_TABLE;

	typedef struct tag_SERVICE_DESCRIPTOR_TABLE {
		SYSTEM_SERVICE_TABLE item1;
		SYSTEM_SERVICE_TABLE item2;
		SYSTEM_SERVICE_TABLE item3;
		SYSTEM_SERVICE_TABLE item4;
	} SERVICE_DESCRIPTOR_TABLE;

	SSDTStruct* KeServiceDescriptorTableShadow = 0;

	ULONGLONG KiServiceTable = 0;

	for (int i = 0; i < 100; i++) {
		if (*(addressAfterPatternChar + i) == 0x4c && *(addressAfterPatternChar + i + 1) == 0x8d && *(addressAfterPatternChar + i + 2) == 0x1d) {
			
			int addr = *(int*)(addressAfterPatternChar + i + 3);


			PUCHAR end = addressAfterPatternChar + i + 7;

			KeServiceDescriptorTableShadow = (SSDTStruct*)(end + addr + sizeof(SSDTStruct));

			KiServiceTable = *(PULONGLONG)(end + addr);

			break;
		}
	}

	UNICODE_STRING winlogon = RTL_CONSTANT_STRING(L"explorer.exe");

	HANDLE winlogonHandle = GetProcessHandle(&winlogon);

	PEPROCESS winlogonProcess = 0;
	NTSTATUS status1 = PsLookupProcessByProcessId(winlogonHandle, &winlogonProcess);

	KeAttachProcess(winlogonProcess);

	ULONGLONG W32pServiceTable = (ULONGLONG)(KeServiceDescriptorTableShadow->pServiceTable);


	// DxgkddiSubmitcommand - syscall 0x1255
	ULONGLONG firstSubmitCommand = GetW32pServiceTableFunc(W32pServiceTable, 0x1255);

	int jmp = *(int*)(firstSubmitCommand + 3);
	PUCHAR jmpEnd = (PUCHAR)(firstSubmitCommand + 7);

	secondSubmitCommand = jmp + jmpEnd;

	orig = *(ULONGLONG*)secondSubmitCommand;

	// NtUserGetDC - syscall 0x100a
	NtUserGetDC = (HDC(*)(HWND hWnd))GetW32pServiceTableFunc(W32pServiceTable, 0x100a);

	// NtGdiPatBlt - syscall 0x1059
	NtGdiPatBlt = (BOOL(*)(HDC hdc, int x, int y, int w, int h, DWORD rop))GetW32pServiceTableFunc(W32pServiceTable, 0x1059);;

	unsigned char* NtGdiExtTextOutW = (unsigned char*)RtlFindExportedRoutineByName(GetSystemModuleBaseAddress("\\SystemRoot\\System32\\win32kfull.sys"), "NtGdiExtTextOutW");

	int jmp1 = 0;
	unsigned char* end1 = 0;

	// Getting GreExtTextOutW
	for (int i = 0; i < 1000; i++) {
		if (*(NtGdiExtTextOutW + i) == 0x8b &&
			*(NtGdiExtTextOutW + i + 1) == 0x54 &&
			*(NtGdiExtTextOutW + i + 2) == 0x24 &&
			*(NtGdiExtTextOutW + i + 3) == 0x78 &&
			*(NtGdiExtTextOutW + i + 4) == 0xe8 &&
			*(NtGdiExtTextOutW + i + 9) == 0x8b &&
			*(NtGdiExtTextOutW + i + 10) == 0xf0){
			end1 = (NtGdiExtTextOutW + i + 9);
			jmp1 = *(int*)(NtGdiExtTextOutW + i + 5);
			break;

		}
	}

	GreExtTextOutW = (void(*)(std::uint64_t dc, std::uint32_t left, std::uint32_t top, std::uint64_t, std::uint64_t, LPCWSTR text, std::uint32_t textSize, std::uint64_t, std::uint64_t, std::uint64_t))(end1 + jmp1);

	PVOID basis = GetSystemModuleBaseAddress("\\SystemRoot\\System32\\win32kbase.sys");

	GreGetDeviceCaps = (int(*)(HDC hdc, int index))RtlFindExportedRoutineByName(basis, "GreGetDeviceCaps");

	uintptr_t hookPtr = reinterpret_cast<uintptr_t>(hookFunc);

	KeQuerySystemTime(&SystemTime);
	RtlTimeToSecondsSince1970(&SystemTime, &timeSec);

	WriteToROMem(secondSubmitCommand, &hookPtr, sizeof(ULONGLONG));

	KeDetachProcess();

	return STATUS_SUCCESS;
}