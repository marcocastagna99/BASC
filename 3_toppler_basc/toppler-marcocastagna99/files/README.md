On Ubuntu 20/22.04 (and similar distros), you should be able to use:
- `sha256sum -c sha256_hashes` to check the integrity of the executable and data files
- `sudo dpkg --add-architecture i386 && sudo apt update` to enable 32-bit support (if you haven't enabled it yet)
- `sudo apt install libsdl1.2debian libsdl1.2debian:i386 libsdl-mixer1.2 libsdl-mixer1.2:i386 zlib1g zlib1g:i386` to install the 32/64-bit libraries needed to run the game

For all other instructions/details, see the README in the assignment GitHub repository.
