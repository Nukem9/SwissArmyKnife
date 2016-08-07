# SwissArmyKnife
Various utilities for extending functionality in [x64dbg](https://github.com/x64dbg/x64dbg).
<br><br>

### Requirements
------
* [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145)

<br>
### IDA Imports
------
* Allows loading and exporting of binary patches (*.dif)
* Allows loading of signature files (*.sig) up to IDA version 6.1

<br>
### Linker MAP Symbols
------
* Allows for loading linker map files (*.map) produced by many compilers. Some information is located [here](http://www.codeproject.com/Articles/3472/Finding-crash-information-using-the-MAP-file). At the moment, exporting such files is not possible with the plugin API.

<br>
### PEiD
------
* Parses and loads [PEiD](https://www.aldeid.com/wiki/PEiD) signature databases.

<br>
### Code Signatures
------
Four different signature styles are supported:
    
1. Code style<br>
    `\x33\xC0\x33\xF6\x48\x89\x44\x24\x42\x89\x44\x24\x4A\x66\x89\x44\x24\x4E\x00\x00\x00\x00\x00\x00\x00\x48\x8B\xF9\xC7\x44\x00\x00\x00\x00\x00\x00\x48\x89\x44\x24\x60\x48`
    <br>
    `xxxxxxxxxxxxxxxxxx???????xxxxx??????xxxxxxxxxxx??????x????xxxxxxxxxxx??????xxxxxxxx`
2. IDA Style<br>
    `33 C0 33 F6 48 89 44 24 42 89 44 24 4A 66 89 44 24 4E ? ? ? ? ? ? ? 48 8B F9 C7 44 ? ? ? ? ? ? 48 89 44 24 60 48`
3. PEiD Style<br>
    `33 C0 33 F6 48 89 44 24 42 89 44 24 4A 66 89 44 24 4E ?? ?? ?? ?? ?? ?? ?? 48 8B F9 C7 44 ?? ?? ?? ?? ?? ?? 48 89 44 24 60 48`
4. CRC32<br>
    `0x754329FB`
        
<br>
### Cipher Detection
------
##### Findcrypt v2 with AES-NI
* Support for finding [AES-NI instructions](https://en.wikipedia.org/wiki/AES_instruction_set#New_instructions).
* Support for finding constants from: Blowfish, Camellia, CAST, CAST256, CRC32, DES, GOST, HAVAL, MARS, MD2, MD5, PKCS_MD2, PKCS_MD5, PKCS_RIPEMD160, PKCS_SHA256, PKCS_SHA384, PKCS_SHA512, PKCS_Tiger, RawDES, RC2, Rijndael, SAFER, SHA256, SHA512, SHARK, SKIPJACK, Square/SHARK, Square, Tiger,Twofish, WAKE, Whirlpool, zlib, SHA-1, RC5_RC6, MD5, MD4, HAVAL

##### AES-Finder
* Searches for 128, 192 and 256-bit AES cipher keys
