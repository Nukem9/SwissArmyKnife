#pragma once

bool ApplySignatureSymbols(char *Path, duint ModuleBase);
bool ApplyDiffSymbols(char *Path, duint UNUSED_ModuleBase);
bool ApplyMapSymbols(char *Path, duint ModuleBase);
bool ExportDiffSymbols(char *Path, duint ModuleBase);
bool ExportMapSymbols(char *Path, duint ModuleBase);