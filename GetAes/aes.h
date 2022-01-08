#pragma once

#include <Windows.h>
#include <fstream>
#include <iostream>

typedef unsigned char uint8;
typedef int int32;

void (*FreeMemory)(__int64);

template<class T>
struct TArray
{
	const wchar_t* c_str() const
	{
		return Data;
	}

	std::string ToString() const
	{
		auto length = std::wcslen(Data);

		std::string str(length, '\0');

		std::use_facet<std::ctype<wchar_t>>(std::locale()).narrow(Data, Data + length, '?', &str[0]);

		return str;
	}

	T* Data;
	INT32 Count;
	INT32 Max;
};

typedef TArray<wchar_t> FString;

enum class EGuidFormats // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/Guid.h#L21
{
	Digits,
	DigitsWithHyphens,
	DigitsWithHyphensInBraces,
	DigitsWithHyphensInParentheses,
	HexValuesInBraces,
	UniqueObjectGuid,
	Short,
	Base36Encoded,
};

struct FAES // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/AES.h#L11
{
	static constexpr unsigned int AESBlockSize = 16;
	struct FAESKey // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/AES.h#L18
	{
		static const int32 KeySize = 32;

		uint8 Key[KeySize];
	};
};

struct FGuid // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/Guid.h#L83
{
	static inline void* (*ToString)(FGuid, FString*, EGuidFormats);
	// https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/Guid.h#L355
	unsigned int A;
	unsigned int B;
	unsigned int C;
	unsigned int D;
};

std::string ToString(FGuid guid, EGuidFormats format) // Cursed don't use
{
	FString temp;
	FGuid::ToString(guid, &temp, format);

	std::string ret(temp.ToString());
	FreeMemory((__int64)temp.c_str());

	return ret;
}

template <typename T = uint8>
void WriteToLog(T msg) // since we only call this function a couple times its fine to keep reopening it.
{
	std::ofstream f;
	f.open("aes.txt", std::ios::out | std::ios::app);
	f << msg << std::endl;
	f.close();
}

struct FPakPlatformFile // https://github.com/EpicGames/UnrealEngine/blob/99b6e203a15d04fc7bbbf554c421a985c1ccb8f1/Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h#L1950
{
	static inline void* (*RegisterEncryptionKey)(FGuid&, FAES::FAESKey&);
	static void RegisterEncryptionKeyDetour(FGuid& InEncryptionKeyGuid, FAES::FAESKey& InKey) // https://github.com/EpicGames/UnrealEngine/blob/99b6e203a15d04fc7bbbf554c421a985c1ccb8f1/Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h#L2107
	{
		std::cout << InKey.Key << std::endl;
		std::string key(reinterpret_cast<char*>(InKey.Key));
		//std::string keyFull = InEncryptionKeyGuid.A + " " + InEncryptionKeyGuid.B + std::string(" ") + std::string(InEncryptionKeyGuid.C + " " + InEncryptionKeyGuid.D + std::string(" Key: "));
		WriteToLog(key);
		RegisterEncryptionKey(InEncryptionKeyGuid, InKey); // Going with the normal procedure
	}
};