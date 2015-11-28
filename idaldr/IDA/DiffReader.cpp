#include "../stdafx.h"

// ********** //
//   READER   //
// ********** //

IDADiffReader::IDADiffReader()
{
	m_FileHandle = nullptr;

	memset(m_Module, 0, sizeof(m_Module));

	m_Patches.reserve(1000);
}

IDADiffReader::~IDADiffReader()
{
	if (m_FileHandle)
		fclose(m_FileHandle);

	m_Patches.clear();
}

bool IDADiffReader::Load(const char *Path)
{
	fopen_s(&m_FileHandle, Path, "rt");

	if (!m_FileHandle)
		return false;

	if (!EnumerateLines())
		return false;

	return true;
}

const char *IDADiffReader::GetModule()
{
	return m_Module;
}

std::vector<DiffFileEntry>&	IDADiffReader::GetPatches()
{
	return m_Patches;
}

bool IDADiffReader::EnumerateLines()
{
	int line = 0;
	char value[1024];

	while (fgets(value, ARRAYSIZE(value), m_FileHandle) != NULL)
	{
		if (strchr(value, '\r'))
			*strchr(value, '\r') = '\0';

		if (strchr(value, '\n'))
			*strchr(value, '\n') = '\0';

		if (!LoadPatch(value, line))
			return false;

		line++;
	}

	return true;
}

bool IDADiffReader::LoadPatch(char *Value, int Line)
{
	/*
	Description

	filename.exe
	00000001: 00 01
	00000003: 00 03
	*/

	// Description
	switch (Line)
	{
	case 0:
		// Description
		_plugin_logprintf("%s\n", Value);

	case 2:
		// File
		strcpy_s(m_Module, Value);

	case 1:
		// Blank line
		return true;
	}

	// Scan for the entry
	DiffFileEntry entry;

	if (sscanf_s(Value, "%llx: %hhX %hhX", &entry.Offset, &entry.Old, &entry.New) <= 0)
		return false;

	m_Patches.push_back(entry);

	return true;
}