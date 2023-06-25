#include "pch.h"
#include "COFFLdr.hpp"


COFFLdr::COFFLdr(COFFData* CoffData) {
	SIZE_T bytesWritten = 0;
	Data = NULL;
	DataSize = 0;
	Coff.Initialized = STATUS_SUCCESS;
	EntryName = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, sizeof(CoffData->EntryName), DRIVER_TAG);

	if (!EntryName) {
		Coff.Initialized = STATUS_ABANDONED;
		return;
	}

	Coff.Initialized = MmCopyVirtualMemory(PsGetCurrentProcess(), CoffData->EntryName, PsGetCurrentProcess(), EntryName, sizeof(CoffData->EntryName), KernelMode, &bytesWritten);

	if (!NT_SUCCESS(Coff.Initialized))
		return;

	if (CoffData->DataSize > 0 && CoffData->Data) {
		DataSize = CoffData->DataSize;

		Coff.Initialized = MmCopyVirtualMemory(PsGetCurrentProcess(), CoffData->Data, PsGetCurrentProcess(), Data, sizeof(CoffData->DataSize), KernelMode, &bytesWritten);

		if (!NT_SUCCESS(Coff.Initialized)) {
			ExFreePoolWithTag(EntryName, DRIVER_TAG);
			return;
		}
	}

	Coff.Data = CoffData->CoffBytes;
	Coff.Header = (PCOFF_FILE_HEADER)Coff.Data;
	Coff.Symbol = (PCOFF_SYMBOL)((PUCHAR)Coff.Data + Coff.Header->PointerToSymbolTable);
	Coff.SecMap = (PSECTION_MAP)ExAllocatePoolWithTag(NonPagedPoolExecute, Coff.Header->NumberOfSections * sizeof(SECTION_MAP), DRIVER_TAG);

	if (!Coff.SecMap) {
		ExFreePoolWithTag(EntryName, DRIVER_TAG);
		Coff.Initialized = STATUS_ABANDONED;
		return;
	}
	Coff.FunMap = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, COFF_FUNMAP_SIZE, DRIVER_TAG);

	if (!Coff.FunMap) {
		ExFreePoolWithTag(EntryName, DRIVER_TAG);
		ExFreePoolWithTag(Coff.SecMap, DRIVER_TAG);
		Coff.Initialized = STATUS_ABANDONED;
		return;
	}
}

/*
* Description:
* COFFLdr::Load is responsible for loading COFF into the driver's memory.
*
* Parameters:
* There are no parameters
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if loaded, else error.
*/
NTSTATUS COFFLdr::Load() {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID currentSection = NULL;
	SIZE_T currentSectionSize = 0;
	SIZE_T bytesWritten = 0;

	for (UINT16 i = 0; i < Coff.Header->NumberOfSections; i++) {
		Coff.Section = (PCOFF_SECTION)((PUCHAR)Coff.Data + sizeof(COFF_FILE_HEADER) + sizeof(COFF_SECTION) * i);

		if (Coff.Section->SizeOfRawData == 0 || !Coff.Section->PointerToRawData) {
			Coff.SecMap[i].Ptr = NULL;
			Coff.SecMap[i].Size = 0;
			continue;
		}

		Coff.SecMap[i].Ptr = (PCHAR)ExAllocatePoolWithTag(NonPagedPoolExecute, Coff.Section->SizeOfRawData, DRIVER_TAG);
		Coff.SecMap[i].Size = Coff.Section->SizeOfRawData;

		if (!Coff.SecMap[i].Ptr)
			goto Cleanup;
		status = MmCopyVirtualMemory(PsGetCurrentProcess(), ((PUCHAR)Coff.Data + Coff.Section->PointerToRawData), PsGetCurrentProcess(), Coff.SecMap[i].Ptr, Coff.Section->SizeOfRawData, KernelMode, &bytesWritten);

		if (!NT_SUCCESS(status))
			goto Cleanup;

		currentSection = NULL;
	}

	status = ProcessSections();

Cleanup:
	if (!NT_SUCCESS(status)) {
		for (UINT16 i = 0; i < Coff.Header->NumberOfSections; i++) {
			Coff.Section = (PCOFF_SECTION)((PUCHAR)Coff.Data + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * i));
			Coff.SecMap[i].Size = Coff.Section->SizeOfRawData;

			if (Coff.SecMap[i].Ptr)
				ExFreePoolWithTag(Coff.SecMap[i].Ptr, DRIVER_TAG);
		}
	}

	return status;
}

/*
* Description:
* COFFLdr::Execute is responsible for executing the COFF's main function.
*
* Parameters:
* There are no parameters
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if found the function and executed, else error.
*/
NTSTATUS COFFLdr::Execute() {
	tMainFunction Main = NULL;
	NTSTATUS status = STATUS_NOT_FOUND;
	UINT32 oldProtection = 0;

	for (UINT32 index = 0; index < Coff.Header->NumberOfSymbols; index++) {
		if (Coff.Symbol[index].First.Name[0]) {
			if (strcmp(Coff.Symbol[index].First.Name, EntryName) == 0) {
				status = STATUS_SUCCESS;
				Main = (tMainFunction)(Coff.SecMap[Coff.Symbol[index].SectionNumber - 1].Ptr + Coff.Symbol[index].Value);
				Main(Data, DataSize);
			}
		}
	}

	return status;
}

/*
* Description:
* COFFLdr::ProcessSymbol is responsible for getting a function address by its name. This function can be either from ntdll or ntoskrnl.
*
* Parameters:
* @symbolName      [LPSTR] -- Symbol's name (library$function format).
*
* Returns:
* @functionAddress [PCHAR] -- Function address if found, else null.
*/
PCHAR COFFLdr::ProcessSymbol(LPSTR symbolName) {
	UNICODE_STRING uFunctionName = { 0 };
	PCHAR functionAddress = NULL;
	PCHAR trimmedSymbolName = strstr(symbolName, IMPORT_FUNCTION_PREFIX) + strlen(IMPORT_FUNCTION_PREFIX);
	PCHAR functionName = strstr(trimmedSymbolName, SYMBOL_DELIMITER) + 1;

	if (!NT_SUCCESS(ConvertAnsiToUnicode(functionName, &uFunctionName))) {
		goto Cleanup;
	}

	if (strncmp(trimmedSymbolName, NTOSKRNL_SYMBOL, strlen(NTOSKRNL_SYMBOL)) == 0)
		functionAddress = (PCHAR)MmGetSystemRoutineAddress(&uFunctionName);
	else if (strncmp(trimmedSymbolName, NTDLL_SYMBOL, strlen(NTDLL_SYMBOL)) == 0)
		functionAddress = (PCHAR)GetSSDTFunctionAddress(functionName);

Cleanup:
	if (uFunctionName.Length != 0) {
		RtlFreeUnicodeString(&uFunctionName);
	}
	return functionAddress;
}

/*
* Description:
* COFFLdr::ProcessSections is responsible for processing the COFF's sections and creating a valid section map.
*
* Parameters:
* There are no parameters.
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if processed correctly, else error.
*/
NTSTATUS COFFLdr::ProcessSections() {
	NTSTATUS status = STATUS_SUCCESS;
	UINT32 symbol = 0;
	PCHAR  symbolName = NULL;
	PCHAR  pFunction = NULL;
	SIZE_T bytesWritten = 0;
	UINT16  functionIndex = 0;
	UINT64 offsetLong = 0;
	UINT32 offset = 0;
	UINT32 relativeOffset = 0;

	for (UINT16 sectionIndex = 0; sectionIndex < Coff.Header->NumberOfSections; sectionIndex++) {
		Coff.Section = (PCOFF_SECTION)((PUCHAR)Coff.Data + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * sectionIndex));
		Coff.Reloc = (PCOFF_RELOC)((PUCHAR)Coff.Data + Coff.Section->PointerToRelocations);

		for (UINT16 relocIndex = 0; relocIndex < Coff.Section->NumberOfRelocations; relocIndex++) {
			if (Coff.Symbol[Coff.Reloc->SymbolTableIndex].First.Name[0] != 0) {
				symbol = (UINT32)(Coff.Symbol[Coff.Reloc->SymbolTableIndex].First.Value[1]);

				if (Coff.Reloc->Type == IMAGE_REL_AMD64_ADDR64) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, PsGetCurrentProcess(), &offsetLong, sizeof(UINT64), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;

					offsetLong = (UINT64)(Coff.SecMap[Coff.Symbol[Coff.Reloc->SymbolTableIndex].SectionNumber - 1].Ptr + (UINT64)offsetLong);
					offsetLong += Coff.Symbol[Coff.Reloc->VirtualAddress].Value;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offsetLong, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT64), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
				}
				else if (Coff.Reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;

					offset = (UINT32)((PCHAR)(Coff.SecMap[Coff.Symbol[Coff.Reloc->SymbolTableIndex].SectionNumber - 1].Ptr + offset) - (PCHAR)(Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress + 4));

					if (offset > MAX_OFFSET) {
						status = STATUS_ABANDONED;
						goto Exit;
					}
					offset += Coff.Symbol[Coff.Reloc->VirtualAddress].Value;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
				}

				else if (Coff.Reloc->Type <= IMAGE_REL_AMD64_REL32_5 && Coff.Reloc->Type >= IMAGE_REL_AMD64_REL32) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, PsGetCurrentProcess(), &offset, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
					relativeOffset = Coff.SecMap[Coff.Symbol[Coff.Reloc->SymbolTableIndex].SectionNumber - 1].Ptr - (Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress + 4);

					if (relativeOffset > MAX_OFFSET) {
						status = STATUS_ABANDONED;
						goto Exit;
					}

					offset += relativeOffset;
					offset += Coff.Symbol[Coff.Reloc->VirtualAddress].Value;
					offset += Coff.Reloc->Type - IMAGE_REL_AMD64_REL32;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
				}
			}
			else
			{
				symbol = Coff.Symbol[Coff.Reloc->SymbolTableIndex].First.Value[1];
				symbolName = ((PCHAR)(Coff.Symbol + Coff.Header->NumberOfSymbols)) + symbol;
				pFunction = ProcessSymbol((PCHAR)symbolName);

				if (!pFunction) {
					status = STATUS_INVALID_PARAMETER;
					goto Exit;
				}

				if (Coff.Reloc->Type == IMAGE_REL_AMD64_ADDR64) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, PsGetCurrentProcess(), &offsetLong, sizeof(UINT64), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
					offsetLong = (UINT64)(Coff.SecMap[Coff.Symbol[Coff.Reloc->SymbolTableIndex].SectionNumber - 1].Ptr + (UINT64)offsetLong);
					offsetLong += Coff.Symbol[Coff.Reloc->VirtualAddress].Value;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offsetLong, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT64), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
				}

				else if (Coff.Reloc->Type == IMAGE_REL_AMD64_REL32) {
					relativeOffset = (Coff.FunMap + (functionIndex * 8)) - (Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress + 4);

					if (relativeOffset > MAX_OFFSET)
						goto Exit;

					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &pFunction, PsGetCurrentProcess(), (Coff.FunMap + (functionIndex * 8)), sizeof(UINT64), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;

					offset = relativeOffset;
					offset += Coff.Symbol[Coff.Reloc->SymbolTableIndex].Value;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;

					functionIndex++;
				}

				else if (Coff.Reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;

					offset = (UINT32)((PCHAR)(Coff.SecMap[Coff.Symbol[Coff.Reloc->SymbolTableIndex].SectionNumber - 1].Ptr + offset) - (PCHAR)(Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress + 4));

					if (offset > MAX_OFFSET) {
						status = STATUS_ABANDONED;
						goto Exit;
					}
					offset += Coff.Symbol[Coff.Reloc->VirtualAddress].Value;
					status = MmCopyVirtualMemory(PsGetCurrentProcess(), &offset, PsGetCurrentProcess(), Coff.SecMap[sectionIndex].Ptr + Coff.Reloc->VirtualAddress, sizeof(UINT32), KernelMode, &bytesWritten);

					if (!NT_SUCCESS(status))
						goto Exit;
				}
			}

			Coff.Reloc = (PCOFF_RELOC)((PUCHAR)Coff.Reloc + sizeof(COFF_RELOC));
		}
	}

Exit:
	return status;
}

/*
* Description:
* COFFLdr::IsInitialized returning whether the initialization was successful or not.
*
* Parameters:
* There are no parameters
*
* Returns:
* @status [NTSTATUS] -- STATUS_SUCCESS if initialized correctly, else error.
*/
NTSTATUS COFFLdr::IsInitialized() {
	return Coff.Initialized;
}

COFFLdr::~COFFLdr() {
	if (NT_SUCCESS(Coff.Initialized)) {
		ExFreePoolWithTag(Coff.FunMap, DRIVER_TAG);
		ExFreePoolWithTag(Coff.SecMap, DRIVER_TAG);
		ExFreePoolWithTag(EntryName, DRIVER_TAG);
	}
}