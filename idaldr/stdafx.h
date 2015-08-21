#pragma once

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <stdint.h>

//
// X64DBG
//
#ifdef _WIN64
#pragma comment(lib, "../pluginsdk/x64_dbg.lib")
#pragma comment(lib, "../pluginsdk/x64_bridge.lib")
#pragma comment(lib, "../pluginsdk/TitanEngine/TitanEngine_x64.lib")
#pragma comment(lib, "../pluginsdk/dbghelp/dbghelp_x64.lib")
#pragma comment(lib, "../zlib/zlib_x64.lib")
#else
#pragma comment(lib, "../pluginsdk/x32_dbg.lib")
#pragma comment(lib, "../pluginsdk/x32_bridge.lib")
#pragma comment(lib, "../pluginsdk/TitanEngine/TitanEngine_x86.lib")
#pragma comment(lib, "../pluginsdk/dbghelp/dbghelp_x86.lib")
#pragma comment(lib, "../zlib/zlib_x86.lib")
#endif // _WIN64

// warning C4091: 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4091)

#include "../pluginsdk/_plugins.h"
#include "../pluginsdk/bridgemain.h"
#include "../pluginsdk/_dbgfunctions.h"
#include "../pluginsdk/TitanEngine/TitanEngine.h"

//
// PLUGIN
//
#include "IDA/Crc16.h"
#include "IDA/Sig.h"
#include "IDA/Diff.h"
#include "Map/Map.h"
#include "Ldr.h"