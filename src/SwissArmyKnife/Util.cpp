#include "stdafx.h"

duint DbgGetCurrentModule()
{
	if (!DbgIsDebugging())
	{
		_plugin_logprintf("The debugger is not running!\n");
		return 0;
	}

	// First get the current code location
	SELECTIONDATA selection;

	if (!GuiSelectionGet(GUI_DISASSEMBLY, &selection))
	{
		_plugin_logprintf("GuiSelectionGet(GUI_DISASSEMBLY) failed\n");
		return 0;
	}

	// Convert the selected address to a module base
	duint moduleBase = DbgFunctions()->ModBaseFromAddr(selection.start);

	if (moduleBase <= 0)
	{
		_plugin_logprintf("Failed to resolve module base at address '0x%llX'\n", (ULONGLONG)selection.start);
		return 0;
	}

	return moduleBase;
}

bool DbgEnumMemoryRanges(std::function<bool(duint Start, duint End)> Callback)
{
	// Request all registered memory ranges from debugger
	MEMMAP map;

	if (!DbgMemMap(&map))
		return false;

	// No memory ranges listed
	if (map.count <= 0)
		return false;

	for (int i = 0; i < map.count; i++)
	{
		duint base	= (duint)map.page[i].mbi.BaseAddress;
		duint end	= base + map.page[i].mbi.RegionSize;

		if (!Callback(base, end))
			return false;
	}

	return true;
}

bool OpenSelectionDialog(const char *Title, const char *Filter, bool Save, bool(*Callback)(char *, duint))
{
	duint moduleBase = DbgGetCurrentModule();

	if (moduleBase <= 0)
		return false;

	// Open a file dialog to select the map or sig
	char buffer[MAX_PATH];
	memset(buffer, 0, sizeof(buffer));

	OPENFILENAMEA ofn;
	memset(&ofn, 0, sizeof(OPENFILENAMEA));

	ofn.lStructSize = sizeof(OPENFILENAMEA);
	ofn.hwndOwner = GuiGetWindowHandle();
	ofn.lpstrFilter = Filter;
	ofn.lpstrFile = buffer;
	ofn.nMaxFile = ARRAYSIZE(buffer);
	ofn.lpstrTitle = Title;
	ofn.Flags = OFN_FILEMUSTEXIST;

	if (Save)
	{
		ofn.lpstrDefExt = strchr(Filter, '\0') + 3;
		ofn.Flags = OFN_OVERWRITEPROMPT;

		if (!GetSaveFileNameA(&ofn))
			return false;
	}
	else
	{
		if (!GetOpenFileNameA(&ofn))
			return false;
	}

	if (!Callback(buffer, moduleBase))
	{
		_plugin_logprintf("An error occurred while applying the file\n");
		return false;
	}

	return true;
}

void StringReplace(std::string& Subject, const std::string& Search, const std::string& Replace)
{
	size_t pos = 0;

	while ((pos = Subject.find(Search, pos)) != std::string::npos)
	{
		Subject.replace(pos, Search.length(), Replace);
		pos += Replace.length();
	}
}