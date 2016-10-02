@echo off
set RELEASEDIR=.\release
rmdir /S /Q %RELEASEDIR%
mkdir %RELEASEDIR%\x32\plugins
mkdir %RELEASEDIR%\x64\plugins

copy bin\x32\SwissArmyKnife.dp32 %RELEASEDIR%\x32\plugins\
copy bin\x64\SwissArmyKnife.dp64 %RELEASEDIR%\x64\plugins\

exit 0