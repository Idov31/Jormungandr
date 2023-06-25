#ifndef COFF_LDR_H
#define COFF_LDR_H

#include "pch.h"

#include "WindowsTypes.hpp"

extern "C" {
    #include "JormungandrCommon.hpp"
}
#include "JormungandrHelper.hpp"

constexpr UINT32 MAX_OFFSET = 0xffffffff;
constexpr SIZE_T COFF_FUNMAP_SIZE = 2048;
constexpr PCHAR SYMBOL_DELIMITER = "$";
constexpr PCHAR IMPORT_FUNCTION_PREFIX = "__imp_";
constexpr PCHAR NTOSKRNL_SYMBOL = "ntoskrnl";
constexpr PCHAR NTDLL_SYMBOL = "ntdll";

#define IMAGE_REL_AMD64_ADDR64          0x0001  // 64-bit address (VA).
#define IMAGE_REL_AMD64_ADDR32NB        0x0003  // 32-bit address w/o image base (RVA).
#define IMAGE_REL_AMD64_REL32           0x0004  // 32-bit relative address from byte following reloc
#define IMAGE_REL_AMD64_REL32_5         0x0009  // 32-bit relative address from byte distance 5 from reloc

#pragma pack(push,1)
typedef struct _COFF_FILE_HEADER
{
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} COFF_FILE_HEADER, * PCOFF_FILE_HEADER;

typedef struct _COFF_SECTION
{
    CHAR    Name[8];
    UINT32  VirtualSize;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLineNumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} COFF_SECTION, * PCOFF_SECTION;

typedef struct _COFF_RELOC
{
    UINT32  VirtualAddress;
    UINT32  SymbolTableIndex;
    UINT16  Type;
} COFF_RELOC, * PCOFF_RELOC;

typedef struct _COFF_SYMBOL
{
    union
    {
        CHAR    Name[8];
        UINT32  Value[2];
    } First;

    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL, * PCOFF_SYMBOL;

typedef struct _SECTION_MAP
{
    PCHAR   Ptr;
    SIZE_T  Size;
} SECTION_MAP, * PSECTION_MAP;

typedef struct _COFF
{
    PVOID             Data;
    PCOFF_FILE_HEADER Header;
    PCOFF_SECTION     Section;
    PCOFF_RELOC       Reloc;
    PCOFF_SYMBOL      Symbol;

    PSECTION_MAP      SecMap;
    PCHAR             FunMap;
    NTSTATUS          Initialized;
} COFF, * PCOFF;
#pragma pack(pop)

typedef VOID(*tMainFunction)(PVOID data, SIZE_T dataSize);

class COFFLdr
{
public:
    COFFLdr(COFFData* CoffData);
    virtual ~COFFLdr();
    NTSTATUS Load();
    NTSTATUS Execute();
    NTSTATUS IsInitialized();

    void* operator new(size_t size) {
        return ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
    }

    void operator delete(void* p) {
        ExFreePoolWithTag(p, DRIVER_TAG);
    }

private:
    COFF Coff;
    PCHAR EntryName;
    PVOID Data;
    SIZE_T DataSize;

    NTSTATUS ProcessSections();
    PCHAR ProcessSymbol(LPSTR symbolName);
};

#endif