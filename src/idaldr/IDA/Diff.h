#pragma once

struct DiffFileEntry
{
	ULONGLONG	Offset;
	BYTE		Old;
	BYTE		New;
};

class IDADiffReader
{
public:

private:
	FILE						*m_FileHandle;

	char						m_Module[MAX_PATH];
	std::vector<DiffFileEntry>	m_Patches;

public:
	IDADiffReader();
	~IDADiffReader();

	bool Load(const char *Path);

	const char					*GetModule();
	std::vector<DiffFileEntry>&	GetPatches();

private:
	bool EnumerateLines();
	bool LoadPatch(char *Value, int Line);
};

class IDADiffWriter
{
public:

private:
	char						m_Description[MAX_PATH];
	char						m_Module[MAX_PATH];
	std::vector<DiffFileEntry>	m_Patches;

public:
	IDADiffWriter();
	~IDADiffWriter();

	bool Generate(const char *Path);

	void SetDescription	(const char *Description);
	void SetModule		(const char *Module);
	void AddPatch		(DiffFileEntry *Entry);

private:
};