#include "../stdafx.h"
#include "../../zlib/zlib.h"

IDASig::IDASig()
{
	memset(&Header, 0, sizeof(IDASigHeader));

	m_LegacyIDB		= false;
	m_FileHandle	= INVALID_HANDLE_VALUE;
	m_FileData		= nullptr;
}

IDASig::~IDASig()
{
	if (m_FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(m_FileHandle);

	if (m_FileData)
		VirtualFree(m_FileData, 0, MEM_RELEASE);
}

bool IDASig::Load(const char *Path)
{
	m_FileHandle = CreateFileA(Path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (m_FileHandle == INVALID_HANDLE_VALUE)
	{
		_plugin_logprintf("Unable to open file\n");
		return false;
	}

	m_FileSize = GetFileSize(m_FileHandle, nullptr);

	if (m_FileSize <= 0)
	{
		_plugin_logprintf("No data in file\n");
		return false;
	}

	m_FileDataBase	= (char *)VirtualAlloc(nullptr, m_FileSize, MEM_COMMIT, PAGE_READWRITE);
	m_FileData		= m_FileDataBase;

	if (!m_FileDataBase)
	{
		_plugin_logprintf("Failed to allocate memory\n");
		return false;
	}

	// Read the file
	if (!ReadFile(m_FileHandle, m_FileDataBase, m_FileSize, &m_FileSize, nullptr))
		return false;

	// Copy the header into its own struct
	memcpy(&Header, m_FileData, sizeof(IDASigHeader));
	IncrementPos(sizeof(IDASigHeader));

	// Integrity check
	if (memcmp(Header.Magic, "IDASGN", 6) != 0)
	{
		_plugin_logprintf("Invalid signature header\n");
		return false;
	}

	// Log and fix up version if needed
	SignatureVersion = Header.Version;
	
	FixupVersion();

	if (Header.Version != IDASIG_VERSION_NEWEST)
	{
		_plugin_logprintf("Unsupported signature version %d\n", Header.Version);
		return false;
	}

	// Read the signature name (stored directly after the header)
	memcpy(SignatureName, m_FileData, Header.SigNameLength);
	SignatureName[Header.SigNameLength] = '\0';

	IncrementPos(Header.SigNameLength);

	// Now check if decompression is needed
	if (Header.SigFlags & IDASIG_FLAG_COMPRESSED)
	{
		if (!Decompress())
		{
			_plugin_logprintf("A fatal error occurred while decompressing\n");
			return false;
		}
	}

	BuildTree(&BaseNode);
	return true;
}

bool IDASig::Support32Bit()
{
	return (Header.AppTypes & IDASIG_APPTYPE_32BIT) != 0;
}

bool IDASig::Support64Bit()
{
	return (Header.AppTypes & IDASIG_APPTYPE_64BIT) != 0;
}

void IDASig::FixupVersion()
{
	//
	// Fix up the header to accommodate for older signature versions
	// NOTE: 'break' is intentionally left out
	//
	switch (Header.Version)
	{
	case IDASIG_VERSION_4:
		m_FileData				-= 2; // qfseek(File, -2, 1);
		Header.Version			= IDASIG_VERSION_4;

	case IDASIG_VERSION_5:
		m_FileData				-= 4; // qfseek(File, -4, 1);
		Header.ModuleCount		= Header.OldModuleCount;
		Header.Version			= IDASIG_VERSION_6;

	case IDASIG_VERSION_6:
		m_LegacyIDB				= true;
		Header.Version			= IDASIG_VERSION_7;
		break;

// 	case IDASIG_VERSION_7:
// 		m_FileData				-= 2; // qfseek(File, -2, 1);
// 		Header.NBytePatterns	= IDASIG_MAX_NODE_BYTES;
// 		Header.Version			= IDASIG_VERSION_8;
// 
// 	case IDASIG_VERSION_8:
// 		Header.Version			= IDASIG_VERSION_9;
// 
// 	case IDASIG_VERSION_9:
// 		break;
	}
}

bool IDASig::Decompress()
{
	//
	// ZLIB
	// 	
	DWORD inflatedOffset = m_FileData - m_FileDataBase;
	DWORD inflatedSize = m_FileSize - inflatedOffset;
	_plugin_logprintf("Compressed data at offset 0x%X with size 0x%X\n", inflatedOffset, inflatedSize);

	std::vector<unsigned char> inflatedData;
	inflatedData.resize(inflatedSize * 3);
	while (true)
	{
		uLongf destLen = inflatedData.size();
		int err = uncompress((Bytef*)inflatedData.data(), &destLen, (Bytef*)m_FileData, inflatedSize);
		if (err == Z_OK) //all good
			break;
		else if (err == Z_BUF_ERROR) //ouput buffer too small
			inflatedData.resize(inflatedData.size() * 2);
		else
		{
			_plugin_logprintf("Decompression error %d!\n", err);
			return false;
		}
	}

	VirtualFree(m_FileData, 0, MEM_RELEASE);
	m_FileData = (char *)VirtualAlloc(nullptr, inflatedData.size(), MEM_COMMIT, PAGE_READWRITE);
	if (!m_FileData)
	{
		_plugin_logprintf("Failed to allocate memory!\n");
		return false;
	}
	memcpy(m_FileData, inflatedData.data(), inflatedData.size());
	return true;
}

/*
Originally reversed and coded by:
	Rheax <rheaxmascot AT gmail DOT com>

More information from:
	https://github.com/JohnDMcMaster/uvudec/wiki/IDA-.sig-file-format
*/

void IDASig::BuildTree(IDASigNode *Node)
{
	uint32_t internalNodeCount = ReadBitshift();

	if (Header.Version <= IDASIG_VERSION_7)
	{
		if (internalNodeCount > 0)
			BuildTreeNode_V7(Node, internalNodeCount);
		else
			BuildLeafNode_V7(Node);
	}
	else
	{
		__debugbreak();
		// FIXME..........................
	}
}

void IDASig::BuildTreeNode_V7(IDASigNode *Node, int InternalNodeCount)
{
	uint32_t relocationBitmask;

	for (int i = 0; i < InternalNodeCount; ++i)
	{
		uint32_t nodeByteCount = ReadByte();
		IDASigNode childNode;

		// Only 32 bytes are allowed
		if (nodeByteCount > IDASIG_MAX_NODE_BYTES)
		{
			printf("Too many bytes\n");
			exit(1);
		}

		uint32_t curRelocationBitmask = 1 << (nodeByteCount - 1);

		if (nodeByteCount >= 16)
			relocationBitmask = ReadRelocationBit();
		else
			relocationBitmask = ReadBitshift();

		// Relocations don't appear until the end
		for (uint32_t j = 0; j < nodeByteCount; j++)
		{
			if (curRelocationBitmask & relocationBitmask)
			{
				childNode.WriteRelocation();
				//_plugin_logprintf("..");
			}
			else
			{
				uint8_t val = ReadByte();

				childNode.WriteByte(val);
				//_plugin_logprintf("%.2X", val);
			}

			curRelocationBitmask >>= 1;
		}

		//_plugin_logprintf(":\n");

		BuildTree(&childNode);
		Node->Nodes.push_back(childNode);
	}
}

void IDASig::BuildLeafNode_V7(IDASigNode *Node)
{
	// Leaf node
	uint32_t readFlags = 0;
	uint32_t funcIndex = 0;

	do
	{
		uint32_t treeBlockLen	= ReadByte();
		uint32_t crc16			= ReadWord();

		do
		{
			uint32_t totalLen		= ReadBitshift();
			uint32_t refCurOffset	= 0;

			//_plugin_logprintf("%d. tree_block_len:0x%.2X a_crc16:0x%.4X total_len:0x%.4X", funcIndex, treeBlockLen, crc16, totalLen);
			funcIndex++;

			do
			{
				std::string name;

				uint32_t delta = ReadBitshift();
				readFlags = ReadByte();

				bool has_negative = readFlags < 32;

				for (int i = 0;; ++i)
				{
					if (i >= 1024)
					{
						printf("reference length exceeded\n");
						exit(1);
					}

					if (readFlags < 32)
						readFlags = ReadByte();

					if (readFlags < 32)
						break;

					name += (char)readFlags;
					readFlags = 0;
				}

				refCurOffset += delta;

				if (refCurOffset == 0)
					printf(" ");

				IDASigLeaf leaf;
				strcpy_s(leaf.Symbol, name.c_str());
				leaf.CrcOffset = treeBlockLen;
				leaf.Crc16 = crc16;
				Node->Leaves.push_back(leaf);

				//_plugin_logprintf(" %.4X:%s", refCurOffset, name.c_str());
			} while (readFlags & 1);

			if (readFlags & 2)
			{
				uint32_t first = ReadBitshift();
				uint32_t second = ReadByte();
				//_plugin_logprintf(" (0x%.4X: 0x%.2X)", first, second);
			}

			// Symbol linked references
			if (readFlags & 4)
			{
				uint32_t a_offset = ReadBitshift();
				uint32_t ref_name_len = ReadByte();

				if (ref_name_len <= 0)
					ref_name_len = ReadBitshift();

				std::string ref_name = std::string(m_FileData, ref_name_len);

				// If last char is 0, we have a special flag set
				if (m_FileData[ref_name_len - 1] == 0)
					a_offset = -a_offset;

				IncrementPos(ref_name_len);
			}
			//_plugin_logprintf("\n");
		} while (readFlags & 0x08);
	} while (readFlags & 0x10);
}

void IDASig::IncrementPos(int Size)
{
	m_FileData += Size;
}

uint32_t IDASig::ReadByte()
{
	uint8_t val = *m_FileData;

	IncrementPos(sizeof(uint8_t));

	return val;
}

uint32_t IDASig::ReadWord()
{
	return (ReadByte() << 8) + ReadByte();
}

uint32_t IDASig::ReadBitshift()
{
	uint32_t val = ReadByte();

	if (val & 0x80)
		return ((val & 0x7F) << 8) + ReadByte();

	return val;
}

uint32_t IDASig::ReadRelocationBit()
{
	uint32_t val = ReadByte();

	if ((val & 0x80) != 0x80)
		return val;

	if ((val & 0xC0) != 0xC0)
		return ((val & 0x7F) << 8) + ReadByte();

	if ((val & 0xE0) != 0xE0)
	{
		uint32_t upper = ((val & 0xFF3F) << 8) + ReadByte();
		return ReadWord() + (upper << 16);
	}

	return ReadWord() + (ReadWord() << 16);
}