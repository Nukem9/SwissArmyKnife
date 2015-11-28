// FindCrypt - find constants used in crypto algorithms
// Copyright 2006 Ilfak Guilfanov <ig@hexblog.com>
// Copyright 2011 Vlad Tsyrklevich <vlad@tsyrklevich.net>
// This is a freeware program.
// This copytight message must be kept intact.

// This plugin looks for constant arrays used in popular crypto algorithms.
// If a crypto algorithm is found, it will rename the appropriate locations
// of the program and put bookmarks on them.

// Version 2-with-mmx
// Adapted to x64dbg
#include <set>
#include <thread>
#include "findcrypt.h"

// Variable types
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned __int32 uint32;
typedef unsigned __int64 uint64;
typedef duint ea_t;

#define msg _plugin_logprintf
#define do_name_anyway DbgSetAutoLabelAt

//--------------------------------------------------------------------------
// wrapper to display current scan address
void showAddr(ea_t ea)
{
	char buf[64];

	sprintf_s(buf, "\nAddress: %p\n", ea);
	GuiAddStatusBarMessage(buf);
}

//--------------------------------------------------------------------------
// template to emulate IDA's functions
template<typename T>
T get_value_type(ea_t ea)
{
	T val = (T)0;

	DbgMemRead((duint)ea, (unsigned char *)&val, sizeof(T));
	return val;
}

//--------------------------------------------------------------------------
// read a single byte
inline uchar get_byte(ea_t ea)
{
	return get_value_type<uchar>(ea);
}

//--------------------------------------------------------------------------
// read a two bytes
inline ushort get_word(ea_t ea)
{
	return get_value_type<ushort>(ea);
}

//--------------------------------------------------------------------------
// read a four bytes
inline uint32 get_long(ea_t ea)
{
	return get_value_type<uint32>(ea);
}

//--------------------------------------------------------------------------
// read a eight bytes
inline uint64 get_qword(ea_t ea)
{
	return get_value_type<uint64>(ea);
}

//--------------------------------------------------------------------------
// read a group of bytes
bool get_many_bytes(ea_t ea, void *buf, size_t size)
{
	return DbgMemRead((duint)ea, (unsigned char *)buf, size);
}

//--------------------------------------------------------------------------
// retrieve the first byte of the specified array
// take into account the byte sex
inline uchar get_first_byte(const array_info_t *a)
{
  const uchar *ptr = (const uchar *)a->array;

#ifndef IS_LITTLE_ENDIAN
  if ( !inf.mf )
    return ptr[0];
#endif // IS_LITTLE_ENDIAN

  return ptr[a->elsize-1];
}

//--------------------------------------------------------------------------
// check that all constant arrays are distinct (no duplicates)
static void verify_constants(const array_info_t *consts)
{
  typedef std::set<std::string> strset_t;
  strset_t myset;
  for ( const array_info_t *ptr=consts; ptr->size != 0; ptr++ )
  {
    std::string s((const char*)ptr->array, ptr->size);
	if (!myset.insert(s).second)
	{
		msg("duplicate array %s!", ptr->name);
		__debugbreak();
	}
  }
}

//--------------------------------------------------------------------------
// match a constant array against the database at the specified address
static bool match_array_pattern(ea_t ea, const array_info_t *ai)
{
  uchar *ptr = (uchar *)ai->array;
  for ( size_t i=0; i < ai->size; i++ )
  {
    switch ( ai->elsize )
    {
      case 1:
        if ( get_byte(ea) != *(uchar*)ptr  )
          return false;
        break;
      case 2:
        if ( get_word(ea) != *(ushort*)ptr )
          return false;
        break;
      case 4:
        if ( get_long(ea) != *(uint32*)ptr )
          return false;
        break;
      case 8:
        if ( get_qword(ea)!= *(uint64*)ptr )
          return false;
        break;
      default:
        msg("interr: unexpected array '%s' element size %d\n",
              ai->name, ai->elsize);
		__debugbreak();
    }
    ptr += ai->elsize;
    ea  += ai->elsize;
  }
  return true;
}

//--------------------------------------------------------------------------
// match a sparse array against the database at the specified address
// NB: all sparse arrays must be word32!
static bool match_sparse_pattern(ea_t ea, const array_info_t *ai)
{
  const word32 *ptr = (const word32*)ai->array;
  if ( get_long(ea) != *ptr++ )
    return false;
  ea += 4;
  for ( size_t i=1; i < ai->size; i++ )
  {
    word32 c = *ptr++;

#ifndef IS_LITTLE_ENDIAN
    if ( inf.mf )
      c = swap32(c);
#endif // IS_LITTLE_ENDIAN

    // look for the constant in the next N bytes
    const size_t N = 64;
    uchar mem[N+4];
    get_many_bytes(ea, mem, sizeof(mem));
    int j;
    for ( j=0; j < N; j++ )
      if ( *(uint32*)(mem+j) == c )
        break;
    if ( j == N )
      return false;
    ea += j + 4;
  }
  return true;
}

//--------------------------------------------------------------------------
// mark a location with the name of the algorithm
// use the first free slot for the marker
static void mark_location(ea_t ea, const char *name)
{
	DbgSetAutoCommentAt(ea, name);
}

//--------------------------------------------------------------------------
// try to find constants at the given address range
static void recognize_constants(ea_t ea1, ea_t ea2)
{
	static bool runOnce = false;

	if (!runOnce)
	{
		runOnce = true;
		verify_constants(non_sparse_consts);
		verify_constants(sparse_consts);
	}

  int array_count = 0, mmx_count = 0;
  msg("Searching for crypto constants...\n");
  for ( ea_t ea=ea1; ea < ea2; ea=ea+1 )
  {
    if ( (ea % 0x10000) == 0 )
    {
		showAddr(ea);
    }
    uchar b = get_byte(ea);
    // check against normal constants
    for ( const array_info_t *ptr=non_sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_array_pattern(ea, ptr) )
      {
        msg("%p: Found const array %s (used in %s)\n", ea, ptr->name, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        do_name_anyway(ea, ptr->name);
        array_count++;
        break;
      }
    }
    // check against sparse constants
    for ( const array_info_t *ptr=sparse_consts; ptr->size != 0; ptr++ )
    {
      if ( b != get_first_byte(ptr) )
        continue;
      if ( match_sparse_pattern(ea, ptr) )
      {
        msg("%p: Found sparse constants for %s\n", ea, ptr->algorithm);
        mark_location(ea, ptr->algorithm);
        array_count++;
        break;
      }
    }
  }

  if(true /*ph.id == PLFM_386*/)
  {
	  msg("Searching for MMX AES instructions...\n");
    for ( ea_t ea=ea1; ea < ea2; ea=ea+1 )
    {
      if ( (ea % 0x10000) == 0 )
      {
		  showAddr(ea);
      }
      uchar b = get_byte(ea);
      if( get_byte(ea) == 0x66 && get_byte(ea + 1) == 0x0f )
      {
        char * instruction = NULL;
        if( get_byte(ea + 2) == 0x38 )
        {
          if( get_byte(ea + 3) == 0xdb ) instruction = "AESIMC";
          if( get_byte(ea + 3) == 0xdc ) instruction = "AESENC";
          if( get_byte(ea + 3) == 0xdd ) instruction = "AESENCLAST";
          if( get_byte(ea + 3) == 0xde ) instruction = "AESDEC";
          if( get_byte(ea + 3) == 0xdf ) instruction = "AESDECLAST";
        }
        else if( get_byte(ea + 2) == 0x3a && get_byte(ea + 3) == 0xdf )
          instruction = "AESKEYGENASSIST";

        if(instruction)
        {
          // We distinguish between whether the bytes we've found are
          //  actual instructions or just possibly instructions
          //if( get_item_head(ea) == ea && isCode(get_flags_novalue(ea)) )
          //  msg("%a: instructions is %s\n", ea, instruction);
          //else
            msg("%p: May be %s\n", ea, instruction);
          mmx_count++;
        }
      }
    }
  }
	msg("Found %d known constant array(s) in total.\n", array_count);
	msg("Found %d possible MMX AES* instruction(s).\n", mmx_count);
}

void FindcryptScanRange(duint Start, duint End)
{
	msg("Starting a scan of range %p to %p...\n", Start, End);

	std::thread t([&]{ recognize_constants(Start, End); });
	t.detach();
}

void FindcryptScanModule()
{
	duint moduleStart = DbgGetCurrentModule();
	duint moduleEnd = moduleStart + DbgFunctions()->ModSizeFromAddr(moduleStart);

	FindcryptScanRange(moduleStart, moduleEnd);
}