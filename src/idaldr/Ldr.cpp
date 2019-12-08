#include "stdafx.h"

int MatchNodeData(IDASigNode *Node, BYTE *Input, size_t Length)
{
	//
	// Matches a pattern of bytes with an input value
	//
	// Returns false when:
	//  Input buffer is too short
	//  Pattern does not match
	//
	// Returns true when:
	//  Pattern and buffer match
	//
	for (int i = 0; i < Node->m_DataIndex; i++)
	{
		// Check if the buffer was too short
		if (Length <= 0)
			return false;

		if (Node->Data[i].Type == 0xFF)
		{
			if (*Input != Node->Data[i].Value)
			{
				// Invalid
				return false;
			}

			Input++;
			Length--;
		}
		else if (Node->Data[i].Type == 0x00)
		{
			//
			// Relocation
			//
			// The bytes here don't matter
			//
			Input++;
			Length--;
		}
	}

	return true;
}

bool MatchSignatureLeaf(IDASigLeaf *Leaf, BYTE *Input, size_t Length)
{
	// Leaves depend on the CRC16
	if (Leaf->Crc16 == 0)
		return true;

	return true;
}

struct SignatureLookup
{
	// IN
	BYTE	*InputBuffer;
	size_t	InputSize;

	// OUT
	char	Name[256];
	int		Length;
};

bool MatchSignatureSymbol(IDASigNode *Base, SignatureLookup *Info)
{
	if (Base->Nodes.size() > 0)
	{
		// Check each node
		for (auto& node : Base->Nodes)
		{
			// Does this node match?
			if (MatchNodeData(&node, Info->InputBuffer, Info->InputSize))
			{
				// It does match, increment the input pointer and decrease length
				Info->InputBuffer	+= node.m_DataIndex;
				Info->InputSize		-= node.m_DataIndex;
				Info->Length		+= node.m_DataIndex;

				// Recurse
				return MatchSignatureSymbol(&node, Info);
			}
		}
	}
	else if (Base->Leaves.size() > 0)
	{
		// Check each leaf
		for (auto itr = Base->Leaves.begin(); itr != Base->Leaves.end(); itr++)
		{
			IDASigLeaf& leaf = *itr;

			// Does this leaf match?
			if (MatchSignatureLeaf(&leaf, Info->InputBuffer, Info->InputSize))
			{
				Info->Length += leaf.CrcOffset;

				// Check the CRC16 if there was one
				if (leaf.Crc16 != 0)
				{
					WORD calc = crc16(Info->InputBuffer, leaf.CrcOffset);

					if (calc != leaf.Crc16)
						return false;
				}

				// This entry has now been used, so remove it
				Base->Leaves.erase(itr);

				strcpy_s(Info->Name, leaf.Symbol);
				return true;
			}
		}
	}

	return false;
}

bool ApplySignatureSymbols(char *Path, duint ModuleBase)
{
	_plugin_logprintf("Opening sig file '%s'\n", Path);

	// Load the signature
	IDASig signature;

	if (!signature.Load(Path))
		return false;

	_plugin_logprintf("Loading signatures in '%s' (Version %d)\n", signature.SignatureName, (int)signature.SignatureVersion);

	// Architecture check
#ifdef _WIN64
	if (!signature.Support64Bit())
	{
		_plugin_logprintf("Signature type (64-bit) is not supported\n");
		return false;
	}
#else
	if (!signature.Support32Bit())
	{
		_plugin_logprintf("Signature type (32-bit) is not supported\n");
		return false;
	}
#endif // _WIN64

	// Get the module size
	duint moduleSize = DbgFunctions()->ModSizeFromAddr(ModuleBase);

	if (moduleSize <= 0)
	{
		_plugin_logprintf("Couldn't get module size from adress 0x%llX\n", ModuleBase);
		return false;
	}

	// Read the entire image to a local buffer for scanning
	PBYTE imageCopy = (PBYTE)VirtualAlloc(nullptr, moduleSize, MEM_COMMIT, PAGE_READWRITE);

	if (!imageCopy || !DbgMemRead(ModuleBase, imageCopy, moduleSize))
	{
		_plugin_logprintf("Failed to make a copy of the remote image\n", ModuleBase);

		if (imageCopy)
			VirtualFree(imageCopy, 0, MEM_RELEASE);

		return false;
	}

	// Scan memory
	UINT32 count = 0;

	for (PBYTE va = imageCopy; va < (imageCopy + moduleSize);)
	{
		SignatureLookup info;
		memset(&info, 0, sizeof(SignatureLookup));

		info.InputBuffer	= va;
		info.InputSize		= (va - imageCopy);

		if (MatchSignatureSymbol(&signature.BaseNode, &info))
		{
			duint remoteVA	= ModuleBase + (size_t)(va - imageCopy);
			va				+= info.Length;

			//_plugin_logprintf("VA: 0x%llx - %s\n", (ULONGLONG)remoteVA, info.Name);

			DbgSetAutoLabelAt(remoteVA, info.Name);
			count++;
		}
		else
		{
			va++;
		}
	}

	// Free memory
	VirtualFree(imageCopy, 0, MEM_RELEASE);

	_plugin_logprintf("Applied %d signatures(s)\n", count);
	return true;
}

bool ApplyDiffSymbols(char *Path, duint UNUSED_ModuleBase)
{
	_plugin_logprintf("Opening dif file '%s'\n", Path);

	// Parse the diff
	IDADiffReader diff;

	if (!diff.Load(Path))
		return false;

	// Convert the module name in the DIFF to an address
	duint moduleBase = DbgFunctions()->ModBaseFromName(diff.GetModule());

	if (!moduleBase)
	{
		_plugin_logprintf("Couldn't get base of module '%s'\n", diff.GetModule());
		return false;
	}

	// Load the image and query the size
	DWORD loadedSize	= 0;
	ULONG_PTR fileMapVa = 0;

	{
		char modPath[MAX_PATH];
		if (DbgFunctions()->ModPathFromAddr(moduleBase, modPath, ARRAYSIZE(modPath)) <= 0)
		{
			_plugin_logprintf("Failed to get module path for '%s'\n", diff.GetModule());
			return false;
		}

		// Load with TitanEngine
		HANDLE fileHandle;
		HANDLE fileMap;

		if (!StaticFileLoad(modPath, GENERIC_READ, true, &fileHandle, &loadedSize, &fileMap, &fileMapVa))
		{
			_plugin_logprintf("Couldn't load a static copy of '%s'\n", modPath);
			return false;
		}
	}

	// Patches use the FILE OFFSET (not virtual offset)
	UINT32 count = 0;

	for (auto& patch : diff.GetPatches())
	{
		// Convert the file offset to a virtual address
		ULONGLONG rva	= ConvertFileOffsetToVA(fileMapVa, (ULONG_PTR)(fileMapVa + patch.Offset), false);
		ULONGLONG va	= (rva == 0) ? 0 : (rva + moduleBase);

		// Get a copy of the original
		if (va)
		{
			BYTE val = 0;

			if (DbgMemRead(va, &val, sizeof(BYTE)) && val != patch.Old)
				_plugin_logprintf("WARNING: Old patch value does not match (Expected 0x%02X / 0x%02X) (File: 0x%llX) (VA: 0x%llX)\n", (ULONG)patch.Old, (ULONG)val, patch.Offset, va);
		}

		// Overwrite
		if (!va || !DbgFunctions()->MemPatch(va, &patch.New, sizeof(BYTE)))
		{
			_plugin_logprintf("Unable to apply a patch (File: 0x%llX) (VA: 0x%llX)\n", patch.Offset, va);
			continue;
		}

		count++;
	}

	// Unload the static copy
	StaticFileUnloadW(nullptr, false, nullptr, 0, nullptr, fileMapVa);

	_plugin_logprintf("Applied %d patch(es) to %s\n", count, diff.GetModule());
	return true;
}

bool ApplyMapSymbols(char *Path, duint ModuleBase)
{
	_plugin_logprintf("Opening map file '%s'\n", Path);

	// Parse the map
	MapFile map;

	if (!map.Load(Path))
		return false;

    auto& segments = map.GetSegments();

	if (!Settings::UseSegments)
		segments.clear();

	// Use the executable sections as segments when they are not supplied
	// in the file
    if (segments.empty())
    {
        char modulePath[MAX_MODULE_SIZE];

        if (DbgFunctions()->ModPathFromAddr(ModuleBase, modulePath, ARRAYSIZE(modulePath)))
        {
            size_t sectionCount = GetPE32Data(modulePath, 0, UE_SECTIONNUMBER);

            for (size_t i = 0; i < sectionCount; i++)
            {
                MapFileSegment segdef;
                memset(&segdef, 0, sizeof(segdef));
                strcpy_s(segdef.Name, (const char*)GetPE32Data(modulePath, i, UE_SECTIONNAME));
                segdef.Start = GetPE32Data(modulePath, i, UE_SECTIONVIRTUALOFFSET);
                segdef.Length = GetPE32Data(modulePath, i, UE_SECTIONVIRTUALSIZE);
                segdef.Id = i + 1;

                segments.push_back(segdef);
            }
        }
    }

    // Print segments to log
    _plugin_logprintf("%d segment(s)\n", segments.size());

    for (auto& seg : segments)
        _plugin_logprintf("  %d: Start=0x%08llX, Length=0x%08llX, %s\n", seg.Id, seg.Start, seg.Length, seg.Name);

	// Apply each symbol manually
    for (auto& sym : map.GetSymbols())
        DbgSetAutoLabelAt((duint)(ModuleBase + map.GetSegmentStart(sym.Id) + sym.Offset), sym.Name);

	_plugin_logprintf("Applied %d symbol(s)\n", map.GetSymbols().size());
	return true;
}

bool ExportDiffSymbols(char *Path, duint ModuleBase)
{
	IDADiffWriter diff;

	// Get the array size of patches needed
	size_t size = 0;
	DbgFunctions()->PatchEnum(nullptr, &size);

	if (size <= 0)
	{
		_plugin_logprintf("No patches found!\n");
		return true;
	}

	// Set basic information
	{
		char temp[MAX_PATH];
		if (!DbgFunctions()->ModNameFromAddr(ModuleBase, temp, true))
		{
			_plugin_logprintf("Couldn't get module name for diff header\n");
			return false;
		}

		diff.SetDescription("Generated by x64dbg (IDALdr - https://github.com/Nukem9/SwissArmyKnife)\n");
		diff.SetModule(temp);
	}

	// Load the image and query the size
	DWORD loadedSize	= 0;
	ULONG_PTR fileMapVa = 0;
	ULONG_PTR fileBase	= 0;

	{
		char modPath[MAX_PATH];
		if (DbgFunctions()->ModPathFromAddr(ModuleBase, modPath, ARRAYSIZE(modPath)) <= 0)
		{
			_plugin_logprintf("Failed to get module path for address '0x%llX'\n", (ULONGLONG)ModuleBase);
			return false;
		}

		// Load with TitanEngine
		HANDLE fileHandle;
		HANDLE fileMap;

		if (!StaticFileLoad(modPath, GENERIC_READ, true, &fileHandle, &loadedSize, &fileMap, &fileMapVa))
		{
			_plugin_logprintf("Couldn't load a static copy of '%s'\n", modPath);
			return false;
		}

		fileBase = GetPE32DataFromMappedFile(fileMapVa, NULL, UE_IMAGEBASE);
	}

	// Store each patch
	DBGPATCHINFO *patchInfo = (DBGPATCHINFO *)BridgeAlloc(size);
	DbgFunctions()->PatchEnum(patchInfo, &size);

	for (UINT32 i = 0; i < (size / sizeof(DBGPATCHINFO)); i++)
	{
		// Is this the module that we want?
		if (DbgFunctions()->ModBaseFromAddr(patchInfo[i].addr) != ModuleBase)
			continue;

		// Translate the virtual address to a file offset
		ULONG_PTR vaoffset		= (patchInfo[i].addr - ModuleBase) + fileBase;
		ULONGLONG fileoffset	= ConvertVAtoFileOffset(fileMapVa, vaoffset, false);

		if (!fileoffset)
		{
			_plugin_logprintf("Unable to convert virtual address 0x%llX to file offset\n", (ULONGLONG)patchInfo[i].addr);
			continue;
		}

		DiffFileEntry entry;
		entry.Offset	= fileoffset;
		entry.Old		= patchInfo[i].oldbyte;
		entry.New		= patchInfo[i].newbyte;

		diff.AddPatch(&entry);
	}

	BridgeFree(patchInfo);
	StaticFileUnloadW(nullptr, false, nullptr, 0, nullptr, fileMapVa);

	// Dump all patches to a file
	if (!diff.Generate(Path))
	{
		_plugin_logprintf("Failed to generate diff file\n");
		return false;
	}

	_plugin_logprintf("Successfully generated diff file at '%s'\n", Path);
	return true;
}

bool ExportMapSymbols(char *Path, duint ModuleBase)
{
	_plugin_logprintf("NOT IMPLEMENTED: Awaiting for x64dbg EnumLabels() API\n");
	return false;
}