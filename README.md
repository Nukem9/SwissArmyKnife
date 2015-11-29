# SwissArmyKnife
Various utilities for extending functionality in [x64dbg](https://github.com/x64dbg/x64dbg).
<br><br>

### IDA Imports
------

<br>
### Linker MAP Symbols
------
    Allows for loading linker map files (*.map) produced by many compilers. An example of one is located [here](http://www.codeproject.com/Articles/3472/Finding-crash-information-using-the-MAP-file). At the moment, exporting such files is not possible with the plugin API.

<br>
### Code Signatures
------
    Four different signature styles are supported:
    
    1. Code style
        `\x33\xC0\x33\xF6\x48\x89\x44\x24\x42\x89\x44\x24\x4A\x66\x89\x44\x24\x4E\x00\x00\x00\x00\x00\x00\x00\x48\x8B\xF9\xC7\x44\x00\x00\x00\x00\x00\x00\x48\x89\x44\x24\x60\x48`
        `xxxxxxxxxxxxxxxxxx???????xxxxx??????xxxxxxxxxxx??????x????xxxxxxxxxxx??????xxxxxxxx`
    2. IDA Style
        `33 C0 33 F6 48 89 44 24 42 89 44 24 4A 66 89 44 24 4E ? ? ? ? ? ? ? 48 8B F9 C7 44 ? ? ? ? ? ? 48 89 44 24 60 48`
    3. PEiD Style
        `33 C0 33 F6 48 89 44 24 42 89 44 24 4A 66 89 44 24 4E ?? ?? ?? ?? ?? ?? ?? 48 8B F9 C7 44 ?? ?? ?? ?? ?? ?? 48 89 44 24 60 48`
    4. CRC32
        `0x754329FB`
        
<br>
### Cipher Detection
------
    ##### Findcrypt v2 with AES-NI
    * Support for finding [AES-NI instructions](https://en.wikipedia.org/wiki/AES_instruction_set#New_instructions)
    * Support for finding constants from: Blowfish, Camellia, CAST, CAST256, CRC32, DES, GOST, HAVAL, MARS, MD2, MD5, PKCS_MD2, PKCS_MD5, PKCS_RIPEMD160, PKCS_SHA256, PKCS_SHA384, PKCS_SHA512, PKCS_Tiger, RawDES, RC2, Rijndael, SAFER, SHA256, SHA512, SHARK, SKIPJACK, Square/SHARK, Square, Tiger,Twofish, WAKE, Whirlpool, zlib, SHA-1, RC5_RC6, MD5, MD4, HAVAL
