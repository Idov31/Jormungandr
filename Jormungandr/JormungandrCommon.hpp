#ifndef JORMUNGANDR_COMMON_H
#define JORMUNGANDR_COMMON_H

#define DRIVER_TAG 'mroJ'
#define DRIVER_PREFIX "Jormungandr: "

struct COFFData {
	PCHAR EntryName;
	PVOID CoffBytes;
	PVOID Data;
	SIZE_T DataSize;
};

extern "C" {
	PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
	NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);
	NTSTATUS NTAPI ZwProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		SIZE_T* NumberOfBytesToProtect,
		ULONG NewAccessProtection,
		PULONG OldAccessProtection);
	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize);
}

#endif