#pragma once

#define IDASIG_VERSION_4 4	// ???
#define IDASIG_VERSION_5 5	// ???
#define IDASIG_VERSION_6 6	// ???
#define IDASIG_VERSION_7 7	// 6.1
#define IDASIG_VERSION_8 8	// 6.4
#define IDASIG_VERSION_9 9	// 6.5

#define IDASIG_VERSION_NEWEST IDASIG_VERSION_7 // Until fixed

#define IDASIG_FLAG_STARTUP			0x01
#define IDASIG_FLAG_USE_CTYPE		0x02
#define IDASIG_FLAG_USE_2BYTE_CTYPE 0x04
#define IDASIG_FLAG_USE_ALT_CTYPE	0x08
#define IDASIG_FLAG_COMPRESSED		0x10

#define IDASIG_APPTYPE_32BIT		0x100
#define IDASIG_APPTYPE_64BIT		0x200

#define IDASIG_MAX_NODE_BYTES		32

#pragma pack(push, 1)
// VERSION 6: 39 bytes total
// VERSION 7: 41 bytes total
// VERSION 8: 43 bytes total
// VERSION 9: 43 bytes total
struct IDASigHeader
{
	char	Magic[6];		//0x0000 Default: IDASGN
	BYTE	Version;		//0x0006 Default: VER_XX
	BYTE	ProcessorId;	//0x0007
	DWORD	FiletypeFlags;	//0x0008
	WORD	OSTypes;		//0x000C
	WORD	AppTypes;		//0x000E
	BYTE	SigFlags;		//0x0010

	char _0x0011[1];

	WORD	OldModuleCount;	//0x0012

	WORD	CTypeCRC;		//0x0014
	char	CTypeName[12];	//0x0016

	BYTE	SigNameLength;	//0x0022
	WORD	AltCTypeCrc;	//0x0023
	DWORD	ModuleCount;	//0x0025

	//WORD	NBytePatterns;	//0x0029 VER_8
};

static_assert(sizeof(IDASigHeader) == 0x29, "Invalid signature header size");
#pragma pack(pop)

class IDASigLeaf
{
public:
	char Symbol[1024];
	WORD CrcOffset;
	WORD Crc16;
	bool Used;
};

class IDASigNode
{
public:
	struct
	{
		BYTE Type;
		BYTE Value;
	} Data[IDASIG_MAX_NODE_BYTES];

	std::vector<IDASigNode> Nodes;
	std::vector<IDASigLeaf> Leaves;

	int m_DataIndex;

private:

public:
	IDASigNode()
	{
		memset(Data, 0, sizeof(Data));
		Nodes.clear();
		Leaves.clear();

		m_DataIndex = 0;
	}

	void WriteByte(BYTE Value)
	{
		Data[m_DataIndex].Type	= 0xFF;
		Data[m_DataIndex].Value	= Value;

		m_DataIndex++;
	}

	void WriteRelocation()
	{
		Data[m_DataIndex].Type	= 0x00;
		Data[m_DataIndex].Value = 0x00;

		m_DataIndex++;
	}
};

class IDASig
{
public:
	IDASigHeader	Header;
	BYTE			SignatureVersion;
	char			SignatureName[256];

	IDASigNode		BaseNode;

private:
	HANDLE	m_FileHandle;
	char	*m_FileDataBase; //only a reference buffer, don't touch this
	char	*m_FileData;
	DWORD	m_FileSize;

	// Kept for consistency
	bool m_LegacyIDB;

public:
	IDASig();
	~IDASig();

	bool Load(const char *Path);
	bool Support32Bit();
	bool Support64Bit();

private:
	void FixupVersion();
	bool Decompress();

	void BuildTree(IDASigNode *Node);
	void BuildTreeNode_V7(IDASigNode *Node, int InternalNodeCount);
	void BuildLeafNode_V7(IDASigNode *Node);

	void IncrementPos(int Size);
	uint32_t ReadByte();
	uint32_t ReadWord();
	uint32_t ReadBitshift();
	uint32_t ReadRelocationBit();
};