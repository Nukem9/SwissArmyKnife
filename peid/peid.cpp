#include "peid.h"
#include "../SwissArmyKnife/Util.h"
#include "../sigmake/Descriptor.h"

bool ApplyPEiDSymbols(char *Path, duint ModuleBase)
{
	FILE *dbFile = nullptr;

	fopen_s(&dbFile, Path, "r");

	if (!dbFile)
		return false;

	//
	// Get a copy of the current module in disassembly
	//
	duint moduleBase = ModuleBase;
	duint moduleSize = DbgFunctions()->ModSizeFromAddr(moduleBase);
	PBYTE processMemory = (PBYTE)BridgeAlloc(moduleSize);

	if (!DbgMemRead(moduleBase, processMemory, moduleSize))
		return false;

	//
	// Buffers to store signature entries
	//
	char buf[4096];
	char name[4096];
	char pattern[4096];

	memset(buf, 0, sizeof(buf));
	memset(name, 0, sizeof(name));
	memset(pattern, 0, sizeof(pattern));

	//
	// Read the file line-by-line
	//
	int totalCount = 0;

	while (fgets(buf, ARRAYSIZE(buf), dbFile) != nullptr)
	{
		if (buf[0] == ';')
		{
			// Comment line
			continue;
		}
		if (buf[0] == '[')
		{
			// '[' indicates the start of a signature
			strcpy_s(name, buf + 1);

			// Trim the ending bracket
			if (strrchr(name, ']'))
				*strrchr(name, ']') = '\0';
		}
		else if (_strnicmp(buf, "ep_only", 7) == 0)
		{
			// 'ep_only' indicates the end of a signature
			bool isEntry = strstr(buf, "true") ? true : false;

			// Replace bad characters
			std::string temp(pattern);

			StringReplace(temp, "\r", "");
			StringReplace(temp, "\n", "");
			StringReplace(temp, "signature = ", "");

			// Scan
			duint result = PEiDPatternScan(temp.c_str(), isEntry, processMemory, moduleBase, moduleSize);

			if (result)
			{
				DbgSetAutoCommentAt(result, name);
				_plugin_logprintf("Match 0x%p - %s\n", result, name);
			}

			// Reset everything
			memset(buf, 0, sizeof(buf));
			memset(name, 0, sizeof(name));
			memset(pattern, 0, sizeof(pattern));

			totalCount++;
		}
		else
		{
			// Anything non-whitespace is appended to the signature
			if (strlen(buf) > 0)
				strcat_s(pattern, buf);
		}
	}

	//
	// Notify user
	//
	_plugin_logprintf("%d signature(s) tested in scan\n", totalCount);

	//
	// Free local copy of module and file handle
	//
	BridgeFree(processMemory);
	fclose(dbFile);
	return true;
}

duint PEiDPatternScan(const char *Pattern, bool EntryPoint, PBYTE ModuleCopy, duint ModuleBase, duint ModuleSize)
{
	//
	// Create the desciptor as a PEiD type
	//
	SIG_DESCRIPTOR *desc = DescriptorFromPEiD(Pattern);

	//
	// Verify
	//
	if (!desc || desc->Count <= 0)
	{
		_plugin_logprintf("Trying to scan with an invalid signature\n");
		return 0;
	}

	//
	// Check if only the entry point should be scanned
	//
	if (EntryPoint)
	{
		//ModuleBase = 0;
		//ModuleSize = 0;
	}

	//
	// Compare function
	//
	auto DataCompare = [](PBYTE Data, SIG_DESCRIPTOR_ENTRY *Entries, ULONG Count)
	{
		ULONG i = 0;

		for (; i < Count; ++Data, ++i)
		{
			if (Entries[i].Wildcard == 0 && *Data != Entries[i].Value)
				return false;
		}

		return i == Count;
	};

	//
	// Scanner loop
	//
	duint match = 0;

	for (duint i = 0; i < ModuleSize; i++)
	{
		PBYTE dataAddr = ModuleCopy + i;

		if (!DataCompare(dataAddr, desc->Entries, desc->Count))
			continue;

		match = ModuleBase + i;
		break;
	}

	BridgeFree(desc);
	return match;
}