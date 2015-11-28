#include "../stdafx.h"

// ********** //
//   WRITER   //
// ********** //

IDADiffWriter::IDADiffWriter()
{
	memset(m_Description, 0, sizeof(m_Description));
	memset(m_Module, 0, sizeof(m_Module));

	m_Patches.reserve(1000);
}

IDADiffWriter::~IDADiffWriter()
{
	m_Patches.clear();
}

bool IDADiffWriter::Generate(const char *Path)
{
	FILE *fileHandle = nullptr;
	fopen_s(&fileHandle, Path, "w");

	if (!fileHandle)
		return false;

	// Write the description
	fputs(m_Description, fileHandle);
	fputs("\n", fileHandle);

	// Module name
	fputs(m_Module, fileHandle);
	fputs("\n", fileHandle);

	// Loop through each patch
	for (auto& entry : m_Patches)
	{
		char buf[256];
		sprintf_s(buf, "%08llx: %02X %02X", entry.Offset, entry.Old, entry.New);

		fputs(buf, fileHandle);
		fputs("\n", fileHandle);
	}

	fclose(fileHandle);
	return true;
}

void IDADiffWriter::SetDescription(const char *Description)
{
	strcpy_s(m_Description, Description);
}

void IDADiffWriter::SetModule(const char *Module)
{
	strcpy_s(m_Module, Module);
}

void IDADiffWriter::AddPatch(DiffFileEntry *Entry)
{
	m_Patches.push_back(*Entry);
}