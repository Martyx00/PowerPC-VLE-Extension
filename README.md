# Renesas NEC850 Architecture Plugin

An architecture extension to allow working with VLE instructions under PowerPC.
When working with a binary that supports VLE just select `ppc` from the architecture list. Most common instructions should be lifted (including couple floating points).

## Install

1. Clone the repo: `git clone https://github.com/Martyx00/PowerPC-VLE-Extension && cd PowerPC-VLE-Extension`
2. Fetch submodules: `git submodule update --init --recursive`
3. CMake things: `mkdir build && cd build && cmake .. -DBN_INSTALL_DIR=/opt/binaryninja` (Replace the `/opt/binaryninja` string at the end with an actual install path of your instance)
4. Make things and install plugin: `make -j4 && cp libVLE_Extension.so ~/.binaryninja/plugins/` (Replace the last part of the command with valid path to the plugins directory for your platform)



