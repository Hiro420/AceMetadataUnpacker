# AceMetadataUnpacker
Simple tool to unpack global-metadata from ACE-protected il2cpp binaries\
The tool targets games where the global-metadata is embedded inside the GameAssembly, such as `Reverse: 1999` and `Nikke`.

# Usage
- Build via Visual Studio 2022 or greater
- Run AceMetaUnpack.exe and specify target GameAssembly.dll \(optionally output path as well\)
- Output metadata should be generated in the folder

## I DO NOT CLAIM ANY RESPONSIBILITY FOR ANY USAGE OF THIS SOFTWARE, THE SOFTWARE IS MADE 100% FOR EDUCATIONAL PURPOSES ONLY

## Notes
- The tool does it's best attempt at detecting if stringliterals are encrypted. If they are, it tries to decrypt them using the standard ACE xor.
- In certain games other parts of the metadata are encrypted. So far i've seen it only happening with `Reverse: 1999`, where strings are encrypted via blowfish. The code for it exists in the repo, you might want to uncomment it's usage.
- Special thanks to [LukeFZ](https://github.com/LukeFZ) for helping me with the blowfish part.

Copyright© Hiro420