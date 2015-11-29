#pragma once

#include "../idaldr/stdafx.h"

#define IS_LITTLE_ENDIAN

#if defined(__GNUC__) || defined(__MWERKS__)
        #define WORD64_AVAILABLE
        typedef unsigned long long word64;
        typedef unsigned long word32;
        typedef unsigned char byte;
        #define W64LIT(x) x##LL
#elif defined(_MSC_VER) || defined(__BCPLUSPLUS__)
        #define WORD64_AVAILABLE
        typedef unsigned __int64 word64;
        typedef unsigned __int32 word32;
        typedef unsigned __int8 byte;
        #define W64LIT(x) x##ui64
#endif

struct array_info_t
{
  const void *array;
  size_t size;
  size_t elsize;
  const char *name;
  const char *algorithm;
};

extern const array_info_t non_sparse_consts[];
extern const array_info_t sparse_consts[];

#define ARR(x)  x, ARRAYSIZE(x), sizeof(x[0]), #x

class Findcrypt
{
public:
	Findcrypt(duint VirtualStart, duint VirtualEnd);
	~Findcrypt();

	void ScanConstants();
	void VerifyConstants(const array_info_t *consts);

protected:
	BYTE GetFirstByte(const array_info_t *ai);
	bool MatchArrayPattern(duint Address, const array_info_t *ai);
	bool MatchSparsePattern(duint Address, const array_info_t *ai);

	void ShowAddress(duint Address);

	template<typename T>
	T GetValueType(duint Address)
	{
		if (Address < m_StartAddress || (Address + sizeof(T)) > m_EndAddress)
			return (T)0;

		return *(T *)&m_Data[Address - m_StartAddress];
	}

	BYTE GetByte(duint Address)
	{
		return GetValueType<BYTE>(Address);
	}

	WORD GetWord(duint Address)
	{
		return GetValueType<WORD>(Address);
	}

	DWORD GetLong(duint Address)
	{
		return GetValueType<DWORD>(Address);
	}

	UINT64 GetQword(duint Address)
	{
		return GetValueType<UINT64>(Address);
	}

	bool GetManyBytes(duint Address, void *Buffer, size_t Size)
	{
		// Boundary check
		if (Address < m_StartAddress || (Address + Size) > m_EndAddress)
			return false;

		memcpy(Buffer, &m_Data[Address - m_StartAddress], Size);
		return true;
	}

private:
	duint m_StartAddress;
	duint m_EndAddress;
	duint m_DataSize;
	PBYTE m_Data;
};

void FindcryptScanRange(duint Start, duint End);
void FindcryptScanModule();

void Plugin_FindcryptLogo();