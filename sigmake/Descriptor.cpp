#include "stdafx.h"

SIG_DESCRIPTOR *AllocDescriptor(ULONG Count)
{
	ULONG totalSize			= sizeof(SIG_DESCRIPTOR) + (sizeof(SIG_DESCRIPTOR_ENTRY) * Count);
	SIG_DESCRIPTOR *temp	= (SIG_DESCRIPTOR *)BridgeAlloc(totalSize);

	if (temp)
		temp->Count = Count;

	// Return value is gnored; BridgeAlloc will kill the program on failure
	return temp;
}

void TrimDescriptor(SIG_DESCRIPTOR *Descriptor)
{
	//
	// This removes any TRAILING wildcards, so
	// the loop starts from the end.
	//
	for (LONG i = Descriptor->Count - 1; i >= 0; i--)
	{
		if (Descriptor->Entries[i].Wildcard == 0)
			break;

		Descriptor->Count--;
	}
}

void ShortenDescriptor(SIG_DESCRIPTOR *Descriptor)
{
	//
	// This shortens patterns by detecting the number
	// of resulting matches. If there is more than one,
	// return. The signature is as short as possible, but
	// still accurate
	//
	std::vector<duint> results;

	for (ULONG init = Descriptor->Count; Descriptor->Count >= 1;)
	{
		// Zero previous values
		results.clear();

		// Scan
		PatternScan(Descriptor, results);

		// Was there more than 1 result?
		if (results.size() > 1)
		{
			if (init != Descriptor->Count)
				Descriptor->Count++;

			return;
		}

		// Otherwise decrease the sig and repeat
		Descriptor->Count--;
	}
}

void DescriptorToCode(SIG_DESCRIPTOR *Descriptor, char **Data, char **Mask)
{
	//
	// Allocate buffers for the resulting strings
	//
	size_t dataSize = Descriptor->Count * strlen("\\x00") + 1;
	size_t maskSize = Descriptor->Count * strlen("x") + 1;

	*Data = (char *)BridgeAlloc(dataSize);
	*Mask = (char *)BridgeAlloc(maskSize);

	for (ULONG i = 0; i < Descriptor->Count; i++)
	{
		if (Descriptor->Entries[i].Wildcard == 0)
		{
			char temp[16];
			sprintf_s(temp, "\\x%02X", (DWORD)Descriptor->Entries[i].Value);

			strcat_s(*Data, dataSize, temp);
			strcat_s(*Mask, maskSize, "x");
		}
		else
		{
			strcat_s(*Data, dataSize, "\\x00");
			strcat_s(*Mask, maskSize, "?");
		}
	}
}

void DescriptorToIDA(SIG_DESCRIPTOR *Descriptor, char **Data)
{
	//
	// Allocate buffers for the resulting strings.
	// Worst case scenario: all are 2 bytes (No wildcards)
	//
	size_t dataSize = Descriptor->Count * strlen("00 ") + 1;
	*Data			= (char *)BridgeAlloc(dataSize);

	for (ULONG i = 0; i < Descriptor->Count; i++)
	{
		if (Descriptor->Entries[i].Wildcard == 0)
		{
			char temp[16];
			sprintf_s(temp, "%02X ", (DWORD)Descriptor->Entries[i].Value);

			strcat_s(*Data, dataSize, temp);
		}
		else
		{
			strcat_s(*Data, dataSize, "? ");
		}
	}

	// Remove the final space
	if (strrchr(*Data, ' '))
		*strrchr(*Data, ' ') = '\0';
}

void DescriptorToPEiD(SIG_DESCRIPTOR *Descriptor, char **Data)
{
	// Similar to IDA, allows for one more ? -> '00 00 ?? 99 99'
	//
	// Allocate buffers for the resulting strings.
	// Worst case scenario: all are 2 bytes (No wildcards)
	//
	size_t dataSize = Descriptor->Count * strlen("00 ") + 1;
	*Data			= (char *)BridgeAlloc(dataSize);

	for (ULONG i = 0; i < Descriptor->Count; i++)
	{
		if (Descriptor->Entries[i].Wildcard == 0)
		{
			char temp[16];
			sprintf_s(temp, "%02X ", (DWORD)Descriptor->Entries[i].Value);

			strcat_s(*Data, dataSize, temp);
		}
		else
		{
			strcat_s(*Data, dataSize, "?? ");
		}
	}

	// Remove the final space
	if (strrchr(*Data, ' '))
		*strrchr(*Data, ' ') = '\0';
}

void DescriptorToCRC(SIG_DESCRIPTOR *Descriptor, char **Data, char **Mask)
{
	// TODO
	__debugbreak();
}

SIG_DESCRIPTOR *DescriptorFromCode(const char *Data, const char *Mask)
{
	//
	// Get the number of byte entries
	//
	ULONG count = (ULONG)strlen(Mask);

	//
	// Allocate the descriptor
	//
	SIG_DESCRIPTOR *desc = AllocDescriptor(count);

	//
	// \x00\x00\x00\x00
	// xx?x
	//
	Data += 2;

	for (ULONG i = 0; i < count; i++)
	{
		if (Mask[0] == 'x')
		{
			desc->Entries[i].Value		= (BYTE)strtol(Data, nullptr, 16);
			desc->Entries[i].Wildcard	= 0;
		}
		else
		{
			desc->Entries[i].Value		= 0;
			desc->Entries[i].Wildcard	= 1;
		}

		Data += 4;
		Mask += 1;
	}

	return desc;
}

SIG_DESCRIPTOR *DescriptorFromIDA(const char *Data)
{
	//
	// Get the number of entries by counting spaces + 1
	//
	size_t dataLen	= strlen(Data);
	ULONG count		= 1;

	for (size_t i = 0; i < dataLen; i++)
	{
		if (Data[i] == ' ')
			count++;
	}

	//
	// Allocate the descriptor
	//
	SIG_DESCRIPTOR *desc = AllocDescriptor(count);

	//
	// 00 44 ? ? 66 ? 88 99
	//
	const char *dataStart	= Data;
	const char *dataEnd		= Data + dataLen;

	for (ULONG i = 0; Data < dataEnd; i++)
	{
		if (Data[0] == '?')
		{
			desc->Entries[i].Value		= 0;
			desc->Entries[i].Wildcard	= 1;

			// Skip over the '?' and space
			Data += 2;
		}
		else
		{
			desc->Entries[i].Value		= (BYTE)strtol(Data, nullptr, 16);
			desc->Entries[i].Wildcard	= 0;

			// Skip over the BYTE and space
			Data += 3;
		}
	}

	return desc;
}

SIG_DESCRIPTOR *DescriptorFromPEiD(const char *Data)
{
	// Replacer function
	auto ReplaceStringInPlace = [](std::string& Subject, const std::string& Search, const std::string& Replace)
	{
		size_t pos = 0;

		while ((pos = Subject.find(Search, pos)) != std::string::npos)
		{
			Subject.replace(pos, Search.length(), Replace);
			pos += Replace.length();
		}
	};

	// This is identical to IDA, just replace '??' with '?'
	std::string newData(Data);
	ReplaceStringInPlace(newData, "??", "?");

	return DescriptorFromIDA(newData.c_str());
}

SIG_DESCRIPTOR *DescriptorFromCRC(const char *Data)
{
	// TODO
	__debugbreak();

	return nullptr;
}