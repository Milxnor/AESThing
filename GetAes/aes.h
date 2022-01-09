// https://github.com/EpicGames/UnrealEngine/blob/99b6e203a15d04fc7bbbf554c421a985c1ccb8f1/Engine/Source/Runtime/PakFile/Private/IPlatformFilePak.cpp#L144 ?

#pragma once

#include <Windows.h>
#include <fstream>
#include <iostream>

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
	int Count;
	int Max;
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

typedef char ANSICHAR;

template <typename T = unsigned char>
void WriteToLog(T msg, std::string filename) // since we only call this function a couple times its fine to keep reopening it.
{
	std::ofstream f;
	f.open(filename, std::ios::out | std::ios::app);
	f << msg << std::endl;
	f.close();
}

struct FAES // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/AES.h#L11
{
	// static inline void* (*EncryptData)(unsigned car* Contents, unsigned int NumBytes, const ANSICHAR* Key); // https://github.com/EpicGames/UnrealEngine/blob/7a807ee5e0358ad0f3f921ea61500a997c9c8a0c/Engine/Source/Runtime/Core/Public/Misc/AES.h#L69
	static constexpr unsigned int AESBlockSize = 16;
	struct FAESKey // https://github.com/EpicGames/UnrealEngine/blob/c3caf7b6bf12ae4c8e09b606f10a09776b4d1f38/Engine/Source/Runtime/Core/Public/Misc/AES.h#L18
	{
		static const int KeySize = 32;

		unsigned char* Key[KeySize];
	};
	/* static void EncryptDataDetour(unsigned car* Contents, unsigned int NumBytes, const ANSICHAR* Key)
	{
		std::string key = Key;
		WriteToLog(key, "EDD");
		return EncryptDataDetour(Contents, NumBytes, Key);
	} */
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

// Usage ToString(Guid, EGuidFormats::Digits)
std::string ToString(FGuid guid, EGuidFormats format) // Cursed don't use
{
	FString temp;
	FGuid::ToString(guid, &temp, format);

	std::string ret(temp.ToString());
	FreeMemory((__int64)temp.c_str());

	return ret;
}

struct FPakPlatformFile // https://github.com/EpicGames/UnrealEngine/blob/99b6e203a15d04fc7bbbf554c421a985c1ccb8f1/Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h#L1950
{
	static inline void* (*RegisterEncryptionKey)(FGuid&, FAES::FAESKey&);
	static void RegisterEncryptionKeyDetour(FGuid& InEncryptionKeyGuid, FAES::FAESKey& InKey) // https://github.com/EpicGames/UnrealEngine/blob/99b6e203a15d04fc7bbbf554c421a985c1ccb8f1/Engine/Source/Runtime/PakFile/Public/IPlatformFilePak.h#L2107
	{
		/*
		
		Printing the InKey.Key

		00000283A74EBE08
		00000283A74EBE08
		00000283A74EFCD8
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EFCD8
		00000283A74EFCD8
		00000283A74EBE08
		00000283A74EBE08
		00000283A74EBE08

		Converting to std::string

		tœF)”†À-¥˜£ıvt }Œ’R
		£g¨ ãğ±¸
		[˜*XÃÀŒ’R
		`ˆ8Ù0Èt„D‹«Î®ÀŒ’R
		…AF^ad3¾—^6ó¤€‡Œ’R
		Ä"€hÙ¦>ÜßÚ&øl
		º^üF>åœÓ.Z!ûü©
		½vWîNü›Êİ·œÃ¹q ‚Œ’R
		]ÏjÂK¼C¼.×rOÛ+ ‚Œ’R
		0‚JËJŒ¼ƒ•&î™ÿ
		òi…÷øPy­Æ[–pGFG ‚Œ’R
		è¡0ı¾bëa    ›NW8±
		ü]Øu<ü]œ­¦ôÛ° ‚Œ’R
		<8Yz„™İAÃK§‡h}|
		Ïj‹¥ä…ïQõöa_¸ç ‚Œ’R
		ã-©‚LåAwsa¶×Q@
		Œ’R

		*/

		/* 
		for (int i = 0; i < InKey.KeySize; i++)
		{
			printf("%02X", *(unsigned char*)InKey.Key[i]); // CRASHES
		}
		*/
		std::string key(reinterpret_cast<char*>(InKey.Key));
		// std::string keyFull = InEncryptionKeyGuid.A + " " + InEncryptionKeyGuid.B + std::string(" ") + std::string(InEncryptionKeyGuid.C + " " + InEncryptionKeyGuid.D + std::string(" Key: "));
		WriteToLog(key, "REK.txt");
		RegisterEncryptionKey(InEncryptionKeyGuid, InKey); // Going with the normal procedure
	}
};