#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

constexpr wchar_t DRIVER_NAME[] = LR"(\\.\Jormungandr)";

struct COFFData {
	PCHAR EntryName;
	PVOID CoffBytes;
	PVOID Data;
	SIZE_T DataSize;
};

int wmain(int argc, const wchar_t* argv[]) {
	COFFData data{};
	DWORD bytesWritten = 0;

	if (argc != 2) {
		std::cerr << "[-] Usage: Jormungandr.exe coff.bin" << std::endl;
		return -1;
	}
	HANDLE hDrv = CreateFile(DRIVER_NAME, GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDrv == INVALID_HANDLE_VALUE)
		return -1;
	
	std::ifstream input(argv[1], std::ios::binary );
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});

	data.Data = NULL;
	data.DataSize = 0;
	data.EntryName = "go";
	data.CoffBytes = buffer.data();

	if (WriteFile(hDrv, &data, sizeof(data), &bytesWritten, NULL))
		std::cout << "[+] Loaded and executed COFF" << std::endl;
	else
		std::cerr << "[-] Failed to load and execute COFF: " << GetLastError() << std::endl;

	CloseHandle(hDrv);
	return 0;
}
