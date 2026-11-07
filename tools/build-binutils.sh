#!/usr/bin/env bash
# Build a big-endian NDS32 binutils (as, ld, objdump, objcopy) on Ubuntu 24.04.
# Reconstructed from the manual steps used during analysis; the flex workaround at the end
# was needed because flex 2.6.4's -P option also mangles upper-case macro names.
set -euo pipefail
PREFIX=${1:-$PWD/nds32-toolchain}; WORK=${2:-$PWD/nds32-build}
apt-get install -y flex bison texinfo build-essential binutils-source
mkdir -p "$WORK" && cd "$WORK"
tar -xf /usr/src/binutils/binutils-*.tar.xz && mv binutils-* src
mkdir build && cd build
../src/configure --target=nds32be-elf --prefix="$PREFIX" --disable-nls --disable-werror \
  --disable-gdb --disable-sim --disable-gprof --disable-gold --disable-ld-plugins
make -j"$(nproc)" MAKEINFO=true all-binutils all-gas || true      # first pass may race on generated lexers
make -j"$(nproc)" MAKEINFO=true all-binutils all-gas
( cd ld && make MAKEINFO=true ldlex.c || true; sed 's/LDLEX_/_/g' lex.yyldlex.c > ldlex.c && touch ldlex.c )
make -j"$(nproc)" MAKEINFO=true all-ld
make MAKEINFO=true install-binutils install-gas install-ld
"$PREFIX/bin/nds32be-elf-ld" --version | head -1
