#pragma once

#include <windows.h>
#include <stdio.h>
#include <vector>
#include <stdint.h>

//
// DISTORM
//
extern "C"
{
#include "distorm/distorm.h"
#include "distorm/mnemonics.h"
#include "distorm/instructions.h"
#include "distorm/prefix.h"
}

//
// SWISSARMYKNIFE
//
#include "../SwissArmyKnife/stdafx.h"

//
// PLUGIN
//
#define CLOSE_WINDOW(handle, global) { (global) = nullptr; DestroyWindow((handle)); }

extern HMODULE g_LocalDllHandle;

#include "resource.h"
#include "Descriptor.h"
#include "SigMake.h"
#include "Dialog/SigMakeDialog.h"
#include "Dialog/Settings.h"
#include "Dialog/SettingsDialog.h"