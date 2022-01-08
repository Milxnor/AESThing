#include <Windows.h>
#include "MinHook/MinHook.h"
#include "aes.h"
#include "skCrypter.h";
#include <iostream>
#include <vector> // for sig scanning

static unsigned __int64* FindPattern(std::string pattern, int times = 0) //not by me
{
	uintptr_t MemoryBase = (uintptr_t)GetModuleHandleA(0);

	static auto patternToByte = [](const char* pattern)
	{
		auto       bytes = std::vector<int>{};
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes.push_back(-1);
			}
			else { bytes.push_back(strtoul(current, &current, 16)); }
		}
		return bytes;
	};

	const auto dosHeader = (PIMAGE_DOS_HEADER)MemoryBase;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)MemoryBase + dosHeader->e_lfanew);

	const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto       patternBytes = patternToByte(pattern.c_str());
	const auto scanBytes = reinterpret_cast<std::uint8_t*>(MemoryBase);

	const auto s = patternBytes.size();
	const auto d = patternBytes.data();

	size_t nFoundResults = 0;

	for (auto i = 0ul; i < sizeOfImage - s; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			if (times != 0)
			{
				if (nFoundResults < times)
				{
					nFoundResults++;                                   // Skip Result To Get nSelectResultIndex.
					found = false;                                     // Make sure we can loop again.
				}
				else
				{
					return (unsigned __int64*)reinterpret_cast<uintptr_t>(&scanBytes[i]);  // Result By Index.
				}
			}
			else
			{
				return (unsigned __int64*)reinterpret_cast<uintptr_t>(&scanBytes[i]);      // Default/First Result.
			}
		}
	}
	return NULL;
}

DWORD WINAPI Main(LPVOID dll)
{

	if (MH_Initialize() != MH_OK)
	{
		MessageBoxA(nullptr, sk("Couldn't start MinHook."), sk("AES Grabber"), MB_OK);
		FreeLibraryAndExitThread(GetModuleHandle(nullptr), 0);
	}

    FILE* fptr;

    AllocConsole();

    freopen_s(&fptr, "CONOUT$", "w", stdout);

    auto ascii = sk(R"(
     ___       _______     _______.  _______ .______          ___      .______   .______    _______ .______      
    /   \     |   ____|   /       | /  _____||   _  \        /   \     |   _  \  |   _  \  |   ____||   _  \     
   /  ^  \    |  |__     |   (----`|  |  __  |  |_)  |      /  ^  \    |  |_)  | |  |_)  | |  |__   |  |_)  |    
  /  /_\  \   |   __|     \   \    |  | |_ | |      /      /  /_\  \   |   _  <  |   _  <  |   __|  |      /     
 /  _____  \  |  |____.----)   |   |  |__| | |  |\  \----./  _____  \  |  |_)  | |  |_)  | |  |____ |  |\  \
/__/     \__\ |_______|_______/     \______| | _| `._____/__/     \__\ |______/  |______/  |_______|| _| `._|
)"); // Star Wars https://www.coolgenerator.com/ascii-text-generator

    std::cout << ascii << sk("\n\nYou are grabbing the AES Key using Milxnor's AES Grabber V1!\n");

	FGuid::ToString = decltype(FGuid::ToString)(FindPattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 17 48 89 55 07 4C 8B FA 4C 8B F1 41 83 E8 01 0F 84 ? ? ? ?"));
	FreeMemory = decltype(FreeMemory)(FindPattern("48 85 C9 0F 84 ? ? ? ? 53 48 83 EC 20 48 89 7C 24 30 48 8B D9 48 8B 3D ? ? ? ? 48 85 FF 0F 84 ? ? ? ? 48 8B 07 4C 8B 40 30 48 8D 05 ? ? ? ? 4C 3B C0"));

	auto REKAddr = FindPattern("48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 20 49 8B D8 48 8B F2");
	FPakPlatformFile::RegisterEncryptionKey = decltype(FPakPlatformFile::RegisterEncryptionKey)(REKAddr);

	MH_CreateHook((void*)REKAddr, FPakPlatformFile::RegisterEncryptionKeyDetour, (PVOID*)(&FPakPlatformFile::RegisterEncryptionKey));
	MH_EnableHook((void*)REKAddr);

    // FreeLibraryAndExitThread((HMODULE)dll, 0);
}

BOOL APIENTRY DllMain( HINSTANCE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, Main, hModule, 0, 0);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

