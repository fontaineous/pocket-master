#!/usr/bin/env bash
# Recipe for the nds32le-elf toolchain used to build SDK examples (Ubuntu 24.04).
# Reconstructed from the manual steps that worked; NOT yet run end-to-end as one script.
# Pieces: binutils 2.42 (+ tools/binutils-nds32-abi-alias.patch), GCC 13.3 (C only), newlib 4.4.
# SDK ABI is "ABI2 FP+" with a single-precision FPU, so libgcc and newlib must be built with it too.
set -euo pipefail
PREFIX=${1:-$PWD/nds32le-toolchain}; WORK=${2:-$PWD/nds32le-build}; export PATH=$PREFIX/bin:$PATH
ABI="-mabi=2fp+ -mext-fpu-sp -mconfig-fpu=2 -mcpu=d1088-spu -fcommon"
apt-get install -y flex bison texinfo build-essential libgmp-dev libmpfr-dev libmpc-dev binutils-source gcc-13-source newlib-source
mkdir -p "$WORK"; cd "$WORK"
for p in binutils:binutils gcc-13:gcc newlib:newlib; do d=${p%%:*}; n=${p##*:}
  mkdir -p src-$n; tar -xf /usr/src/$d/*.tar.* -C src-$n --strip-components=1; done
# 1. binutils (needs the ABI alias patch: GCC 13 passes -mabi=v2fp+, gas 2.42 only knows v2fpp)
patch -d src-binutils -p0 < /dev/null || true
( cd src-binutils && patch -p0 gas/config/tc-nds32.c < "$OLDPWD/../tools/binutils-nds32-abi-alias.patch" || true )
mkdir b-bin && cd b-bin
../src-binutils/configure --target=nds32le-elf --prefix="$PREFIX" --disable-nls --disable-werror --disable-gdb --disable-sim --disable-gprof --disable-gold --disable-ld-plugins
make -j"$(nproc)" MAKEINFO=true all-binutils all-gas || make MAKEINFO=true all-binutils all-gas
# flex 2.6.4 -P mangles upper-case macros in ld's lexer: strip LDLEX_ from the generated file
( cd ld && make MAKEINFO=true ldlex.c || true; sed 's/LDLEX_/_/g' lex.yyldlex.c > ldlex.c; touch ldlex.c )
make -j"$(nproc)" MAKEINFO=true all-ld
make MAKEINFO=true install-binutils install-gas install-ld; cd ..
# 2. GCC (freestanding C), then libgcc with the SDK ABI
mkdir b-gcc && cd b-gcc
../src-gcc/configure --target=nds32le-elf --prefix="$PREFIX" --enable-languages=c --without-headers --with-newlib --disable-nls --disable-shared --disable-threads --disable-multilib --disable-libssp --disable-libgomp --disable-libquadmath --disable-libatomic --disable-libstdcxx --disable-bootstrap --disable-werror
make -j"$(nproc)" all-gcc && make install-gcc
make -j"$(nproc)" all-target-libgcc "CFLAGS_FOR_TARGET=-O2 -g $ABI" && make install-target-libgcc; cd ..
# 3. newlib with the same ABI; the SDK supplies putchar/nds_write, build/sdk-example/syscalls.c bridges them
mkdir b-newlib && cd b-newlib
../src-newlib/configure --target=nds32le-elf --prefix="$PREFIX" --disable-nls --disable-multilib --disable-libgloss --disable-newlib-supplied-syscalls --enable-newlib-reent-small --disable-newlib-fvwrite-in-streamio --disable-newlib-io-float
make -j"$(nproc)" all-target-newlib "CFLAGS_FOR_TARGET=-O2 -g $ABI" && make install-target-newlib "CFLAGS_FOR_TARGET=-O2 -g $ABI"
nds32le-elf-ar rc "$PREFIX/nds32le-elf/lib/libgloss.a"   # empty: GCC's nds32 spec asks for -lgloss
