#include "pch.h"
#include "JormungandrHelper.hpp"

/*
* Description:
* ConvertAnsiToUnicode is responsible for converting ANSI string to UNICODE.
*
* Parameters:
* @ansiString [PCHAR]			-- Source string to convert.
* @outString  [PUNICODE_STRING] -- Output unicode string.
*
* Returns:
* @status	  [NTSTATUS]	    -- Whether successfuly converted or not.
*/
NTSTATUS ConvertAnsiToUnicode(PCHAR ansiString, PUNICODE_STRING outString) {
	ANSI_STRING aFunctionName = { 0 };
	RtlInitAnsiString(&aFunctionName, ansiString);
	return RtlAnsiStringToUnicodeString(outString, &aFunctionName, TRUE);;
}

/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern		  [PCUCHAR]	    -- Pattern to search for.
* @wildcard		  [UCHAR]		-- Used wildcard.
* @len			  [ULONG_PTR]	-- Pattern length.
* @base			  [const PVOID] -- Base address for searching.
* @size			  [ULONG_PTR]	-- Address range to search in.
* @foundIndex	  [PULONG]	    -- Index of the found signature.
* @relativeOffset [ULONG]		-- If wanted, relative offset to get from.
*
* Returns:
* @address		  [PVOID]	    -- Pattern's address if found, else 0.
*/
PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset) {
	bool found;

	if (pattern == NULL || base == NULL || len == 0 || size == 0)
		return NULL;

	for (ULONG_PTR i = 0; i < size - len; i++) {
		found = true;

		for (ULONG_PTR j = 0; j < len; j++) {
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
				found = false;
				break;
			}
		}

		if (found) {
			if (foundIndex)
				*foundIndex = i;
			return (PUCHAR)base + i + relativeOffset;
		}
	}

	return NULL;
}

/*
* Description:
* GetModuleBase is responsible for getting the base address of given module inside a given process.
*
* Parameters:
* @Process    [PEPROCESS] -- The process to search on.
* @moduleName [WCHAR*]	  -- Module's name to search.
*
* Returns:
* @moduleBase [PVOID]	  -- Base address of the module if found, else null.
*/
PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName) {
	PVOID moduleBase = NULL;
	LARGE_INTEGER time = { 0 };
	time.QuadPart = -100ll * 10 * 1000;

	PREALPEB targetPeb = (PREALPEB)PsGetProcessPeb(Process);

	if (!targetPeb) {
		return moduleBase;
	}

	for (int i = 0; !targetPeb->LoaderData && i < 10; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	if (!targetPeb->LoaderData) {
		return moduleBase;
	}

	// Getting the module's image base.
	for (PLIST_ENTRY pListEntry = targetPeb->LoaderData->InLoadOrderModuleList.Flink;
		pListEntry != &targetPeb->LoaderData->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink) {

		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (_wcsnicmp(pEntry->FullDllName.Buffer, moduleName, pEntry->FullDllName.Length / sizeof(wchar_t) - 4) == 0) {
			moduleBase = pEntry->DllBase;
			break;
		}
	}

	return moduleBase;
}

/*
* Description:
* GetFunctionAddress is responsible for getting the function address inside given module from its EAT.
*
* Parameters:
* @moduleBase      [PVOID] -- Module's image base address.
* @functionName    [CHAR*] -- Function name to search.
*
* Returns:
* @functionAddress [PVOID] -- Function address if found, else null.
*/
PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName) {
	PVOID functionAddress = NULL;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

	// Checking that the image is valid PE file.
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return functionAddress;
	}

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)moduleBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return functionAddress;
	}

	IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

	if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
		return functionAddress;
	}

	// Iterating the export directory.
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addresses = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfFunctions);
	WORD* ordinals = (WORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNameOrdinals);
	DWORD* names = (DWORD*)((PUCHAR)moduleBase + exportDirectory->AddressOfNames);

	for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
		if (_stricmp((char*)((PUCHAR)moduleBase + names[j]), functionName) == 0) {
			functionAddress = (PUCHAR)moduleBase + addresses[ordinals[j]];
			break;
		}
	}

	return functionAddress;
}

/*
* Description:
* GetSSDTAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
NTSTATUS GetSSDTAddress() {
	ULONG infoSize;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PRTL_PROCESS_MODULES info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info) {
			ExFreePoolWithTag(info, DRIVER_TAG);
			info = NULL;
		}

		info = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!info)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		goto CleanUp;

	PRTL_PROCESS_MODULE_INFORMATION modules = info->Modules;

	for (ULONG i = 0; i < info->NumberOfModules; i++) {
		if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			ntoskrnlBase = modules[i].ImageBase;
			break;
		}
	}

	if (!ntoskrnlBase)
		goto CleanUp;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		goto CleanUp;

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		goto CleanUp;

	PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
		if (strcmp((const char*)section->Name, ".text") == 0) {
			ssdtRelativeLocation = FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, NULL);

			if (ssdtRelativeLocation) {
				status = STATUS_SUCCESS;
				ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRelativeLocation + *(PULONG)((PUCHAR)ssdtRelativeLocation + 3) + 7);
				break;
			}
		}
	}

CleanUp:
	if (info)
		ExFreePoolWithTag(info, DRIVER_TAG);
	return status;
}

/*
* Description:
* GetSSDTFunctionAddress is responsible for getting the SSDT's location.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found, else error.
*/
PVOID GetSSDTFunctionAddress(CHAR* functionName) {
	KAPC_STATE state;
	PEPROCESS CsrssProcess = NULL;
	PVOID functionAddress = NULL;
	PSYSTEM_PROCESS_INFO originalInfo = NULL;
	PSYSTEM_PROCESS_INFO info = NULL;
	ULONG infoSize = 0;
	ULONG index = 0;
	UCHAR syscall = 0;
	HANDLE csrssPid = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (originalInfo) {
			ExFreePoolWithTag(originalInfo, DRIVER_TAG);
			originalInfo = NULL;
		}

		originalInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(PagedPool, infoSize, DRIVER_TAG);

		if (!originalInfo)
			return functionAddress;

		status = ZwQuerySystemInformation(SystemProcessInformation, originalInfo, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !originalInfo)
		goto CleanUp;

	// Using another info variable to avoid BSOD on freeing.
	info = originalInfo;

	// Iterating the processes information until our pid is found.
	while (info->NextEntryOffset) {
		if (info->ImageName.Buffer && info->ImageName.Length > 0) {
			if (_wcsicmp(info->ImageName.Buffer, L"csrss.exe") == 0) {
				csrssPid = info->UniqueProcessId;
				break;
			}
		}
		info = (PSYSTEM_PROCESS_INFO)((PUCHAR)info + info->NextEntryOffset);
	}

	if (csrssPid == 0)
		goto CleanUp;
	status = PsLookupProcessByProcessId(csrssPid, &CsrssProcess);

	if (!NT_SUCCESS(status))
		goto CleanUp;

	// Attaching to the process's stack to be able to walk the PEB.
	KeStackAttachProcess(CsrssProcess, &state);
	PVOID ntdllBase = GetModuleBase(CsrssProcess, L"C:\\Windows\\System32\\ntdll.dll");

	if (!ntdllBase) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}
	PVOID ntdllFunctionAddress = GetFunctionAddress(ntdllBase, functionName);

	if (!ntdllFunctionAddress) {
		KeUnstackDetachProcess(&state);
		goto CleanUp;
	}

	// Searching for the syscall.
	while (((PUCHAR)ntdllFunctionAddress)[index] != RETURN_OPCODE) {
		if (((PUCHAR)ntdllFunctionAddress)[index] == MOV_EAX_OPCODE) {
			syscall = ((PUCHAR)ntdllFunctionAddress)[index + 1];
		}
		index++;
	}
	KeUnstackDetachProcess(&state);

	if (syscall != 0)
		functionAddress = (PUCHAR)ssdt->ServiceTableBase + (((PLONG)ssdt->ServiceTableBase)[syscall] >> 4);

CleanUp:
	if (CsrssProcess)
		ObDereferenceObject(CsrssProcess);

	if (originalInfo) {
		ExFreePoolWithTag(originalInfo, DRIVER_TAG);
		originalInfo = NULL;
	}

	return functionAddress;
}