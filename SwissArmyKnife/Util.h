#pragma once

duint DbgGetCurrentModule();
bool OpenSelectionDialog(const char *Title, const char *Filter, bool Save, bool(*Callback)(char *, duint));