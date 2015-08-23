#pragma once

#include "../idaldr/stdafx.h"

bool ApplyPEiDSymbols(char *Path, duint ModuleBase);
duint PEiDPatternScan(const char *Pattern, bool EntryPoint, PBYTE ModuleCopy, duint ModuleBase, duint ModuleSize);