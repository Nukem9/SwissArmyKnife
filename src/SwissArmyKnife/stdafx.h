#pragma once

#define PLUGIN_NAME		"SwissArmyKnife"
#define PLUGIN_VERSION	001

//
// WINDOWS
//
#include <windows.h>

//
// X64DBG
//
#define dprintf _plugin_logprintf

#ifdef _WIN64
#pragma comment(lib, "../pluginsdk/x64dbg.lib")
#pragma comment(lib, "../pluginsdk/x64bridge.lib")
#pragma comment(lib, "../pluginsdk/TitanEngine/TitanEngine_x64.lib")
#pragma comment(lib, "../pluginsdk/dbghelp/dbghelp_x64.lib")
#else
#pragma comment(lib, "../pluginsdk/x32dbg.lib")
#pragma comment(lib, "../pluginsdk/x32bridge.lib")
#pragma comment(lib, "../pluginsdk/TitanEngine/TitanEngine_x86.lib")
#pragma comment(lib, "../pluginsdk/dbghelp/dbghelp_x86.lib")
#endif // _WIN64

// warning C4091: 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4091)

#include "../pluginsdk/_plugins.h"
#include "../pluginsdk/bridgemain.h"
#include "../pluginsdk/_dbgfunctions.h"
#include "../pluginsdk/TitanEngine/TitanEngine.h"

//
// EVERYTHING ELSE
//
#include "../idaldr/stdafx.h"
#include "../sigmake/stdafx.h"
#include "../peid/peid.h"
#include "../findcrypt/findcrypt.h"
#include "../aes-finder/aes-finder.h"

#include "Util.h"
#include "Plugin.h"