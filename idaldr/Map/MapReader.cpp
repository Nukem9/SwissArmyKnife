#include "../stdafx.h"

MapFile::MapFile()
{
	m_FileHandle	= INVALID_HANDLE_VALUE;
	m_FileDataBase	= nullptr;
	m_FileData		= nullptr;
	m_Symbols.reserve(5000);
}

MapFile::~MapFile()
{
	if (m_FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(m_FileHandle);

	if (m_FileDataBase)
		VirtualFree(m_FileDataBase, 0, MEM_RELEASE);

	m_Segments.clear();
	m_Symbols.clear();
}

bool MapFile::Load(const char *Path)
{
	m_FileHandle = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (m_FileHandle == INVALID_HANDLE_VALUE)
	{
		_plugin_logprintf("Unable to open file\n");
		return false;
	}

	DWORD fileSize = GetFileSize(m_FileHandle, nullptr);

	if (fileSize <= 0)
	{
		_plugin_logprintf("No data in file\n");
		return false;
	}

	m_FileDataBase	= (char *)VirtualAlloc(nullptr, fileSize, MEM_COMMIT, PAGE_READWRITE);
	m_FileData		= m_FileDataBase;

	if (!m_FileDataBase)
	{
		_plugin_logprintf("Failed to allocate memory\n");
		return false;
	}

	if (!ReadFile(m_FileHandle, m_FileData, fileSize, &fileSize, nullptr))
	{
		_plugin_logprintf("Failed to read file data\n");
		return false;
	}

	if (!LoadSegments())
		return false;

	if (!LoadSymbols())
		return false;

	return true;
}

std::map<int, MapFileSegment>& MapFile::GetSegments()
{
	return m_Segments;
}

std::vector<MapFileSymbol>& MapFile::GetSymbols()
{
	return m_Symbols;
}

bool MapFile::EnumerateLines(char *Start, int Type)
{
	int line	= 0;
	char *ptr	= Start;
	char *eol	= nullptr;

	for (; *ptr; ptr++)
	{
		switch (*ptr)
		{
		case '\n':
			line++;

		case '\r':
		case ' ':
		case '\t':
			continue;
		}

		// Line #0 is the heading
		if (line < 1)
			continue;

		// Terminate the line
		eol = strchr(ptr, '\r');

		if (!eol)
			eol = strchr(ptr, '\n');

		if (eol)
			*eol = '\0';

		// If the delimiter is not present, the line is not valid
		if (!strchr(ptr, ':'))
			break;

		if (Type == 'SEGM' && !LoadSegment(ptr))
			break;
		
		if (Type == 'SYMB' && !LoadSymbol(ptr))
			break;

		if (eol)
			ptr = eol + 1;
	}

	if (eol)
		*eol = '\r';

	m_FileData = ptr;
	return true;
}

bool MapFile::LoadSegments()
{
	/*
	 Start         Length     Name                   Class
	 0001:00000000 000000030H .init                  CODE
	*/
	char *startPos = strstr(m_FileData, "Start");

	if (!startPos)
	{
		_plugin_logprintf("Couldn't find starting position for segments\n");
		return false;
	}

	return EnumerateLines(startPos, 'SEGM');
}

char *GrabToken(char *Dest, char *Src)
{
	// Skip spaces
	while (*Src == ' ' || *Src == '\t')
		Src++;

	char *bufEnd = strchr(Src, ' ');

	// Case with ':'
	{
		char *delim = strchr(Src, ':');

		if (delim && (delim < bufEnd))
			bufEnd = delim;
	}

	if (bufEnd)
		*bufEnd = '\0';

	strcpy(Dest, Src);

	return ((bufEnd) ? (bufEnd + 1) : nullptr);
}

bool MapFile::LoadSegment(char *Line)
{
	// ID:BASE LENGTH NAME CLASS
	char tokens[8][256];
	memset(tokens, 0, sizeof(tokens));

	// Skip spaces and make a copy
	while (*Line == ' ' || *Line == '\t')
		Line++;

	char buf[256];
	strncpy_s(buf, Line, 255);

	// Parse each token
	char *bufPtr	= buf;
	int tokenIndex	= 0;

	for (int i = 0; i < ARRAYSIZE(tokens); i++)
	{
		bufPtr = GrabToken(tokens[i], bufPtr);

		if (!bufPtr)
			break;
	}

	MapFileSegment segdef;
	strcpy_s(segdef.Name, tokens[3]);
	strcpy_s(segdef.Class, tokens[4]);

	if (sscanf_s(tokens[0], "%x", &segdef.Id) <= 0)
		return false;

	if (sscanf_s(tokens[1], "%llx", &segdef.Start) <= 0)
		return false;

	if (sscanf_s(tokens[2], "%llxH", &segdef.Length) <= 0)
		return false;

	// Segment definitions are adjusted to skip the PE header,
	// which is never defined in the file (1 page, 4096 bytes)
	segdef.Start += 4096;

    m_Segments.insert({ segdef.Id, segdef });

	return true;
}

bool MapFile::LoadSymbols()
{
	/*
	  Address         Publics by Value
	  0001:00000000       _init_proc
	*/
	char *startPos = strstr(m_FileData, "Address");

	if (!startPos)
	{
		_plugin_logprintf("Couldn't find starting position for symbols\n");
		return false;
	}

	return EnumerateLines(startPos, 'SYMB');
}

bool MapFile::LoadSymbol(char *Line)
{
	// ID:OFFSET NAME
	char tokens[5][256];
	memset(tokens, 0, sizeof(tokens));

	// Skip spaces and make a copy
	while (*Line == ' ' || *Line == '\t')
		Line++;

	char buf[256];
	strncpy_s(buf, Line, 255);

	// Parse each token
	char *bufPtr	= buf;
	int tokenIndex	= 0;

	for (int i = 0; i < ARRAYSIZE(tokens); i++)
	{
		bufPtr = GrabToken(tokens[i], bufPtr);

		if (!bufPtr)
			break;
	}

	MapFileSymbol symdef;
	strcpy_s(symdef.Name, tokens[2]);

	if (sscanf_s(tokens[0], "%x", &symdef.Id) <= 0)
		return false;

	if (sscanf_s(tokens[1], "%llx", &symdef.Offset) <= 0)
		return false;

	m_Symbols.push_back(symdef);

	return true;
}