#pragma once

duint DbgGetCurrentModule();
bool DbgEnumMemoryRanges(std::function<bool(duint Start, duint End)> Callback);
bool OpenSelectionDialog(const char *Title, const char *Filter, bool Save, bool(*Callback)(char *, duint));
void StringReplace(std::string& Subject, const std::string& Search, const std::string& Replace);