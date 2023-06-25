#ifndef JORMUNGANDR_HELPER_H
#define JORMUNGANDR_HELPER_H

#include "pch.h"
#include "WindowsTypes.hpp"

extern "C" {
	#include "JormungandrCommon.hpp"
}

inline PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;
constexpr UCHAR RETURN_OPCODE = 0xC3;
constexpr UCHAR MOV_EAX_OPCODE = 0xB8;

NTSTATUS ConvertAnsiToUnicode(PCHAR ansiString, PUNICODE_STRING outString);
PVOID FindPattern(PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const PVOID base, ULONG_PTR size, PULONG foundIndex, ULONG relativeOffset);
PVOID GetModuleBase(PEPROCESS Process, WCHAR* moduleName);
PVOID GetFunctionAddress(PVOID moduleBase, CHAR* functionName);
NTSTATUS GetSSDTAddress();
PVOID GetSSDTFunctionAddress(CHAR* functionName);

#endif