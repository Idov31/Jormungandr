#include <Windows.h>
 
DECLSPEC_IMPORT ULONG __cdecl ntoskrnl$DbgPrint(PCSTR Format, ...);

void go(PVOID data, SIZE_T dataSize) {
    ntoskrnl$DbgPrint("Hello from COFF!\n");
}