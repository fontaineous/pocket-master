#!/usr/bin/env bash
# Build the MVsilicon SDK application BT_Audio_APP (public SDK sources + prebuilt vendor libs) with the nds32le toolchain.
#   build.sh <SDK_DIR> <TOOLCHAIN_PREFIX> <OUT_DIR>
# Findings baked in (see docs/FINDINGS.md section 15): -fcommon, -fgnu89-inline, ABI2 FP+, case-insensitive header shims,
# no -D1088, os_cpu_a.S 'movi' -> 'li', placeholder stubs for Andes libdsp. USB-host/udisk sources are built because the
# default app_config.h enables them; the vendor's real config (and thus file set) is unknown.
set -uo pipefail
SDK=${1:?SDK dir}; TC=${2:?toolchain prefix}; OUT=${3:?out dir}
export PATH=$TC/bin:$PATH
A=$SDK/BT_Audio_APP; M=$SDK/MVsB1_Base_SDK; ABI="-mabi=2fp+ -mext-fpu-sp -mconfig-fpu=2"
mkdir -p "$OUT/obj" "$OUT/shim"; rm -f "$OUT"/obj/*.o
# case-insensitive header shims (SDK was written on Windows)
for h in freertos.h EOSDEF.h eosdef.h rda5807.h hdmi_in_Mode.h aivs_encode.h xm_xiaoai_api.h; do
  r=$(find "$SDK" -iname "$h" -not -path '*/.git/*' | head -1); [ -n "$r" ] && ln -sf "$r" "$OUT/shim/$h"; done
INC="-I$OUT/shim -I$A/bt_audio_app_src/libopus/app -I$A/bt_audio_app_src/xiaomi_ai -I$A/bt_audio_app_src/audio -I$SDK/develop_lib/util -I$SDK/develop_lib -I$SDK/develop_lib/trace
 -I$A/bt_audio_app_src/ai/md5 -I$A/bt_audio_app_src/ai/speex/include/speex -I$A/bt_audio_app_src/ai/speex/include -I$A/bt_audio_app_src/ai/speex/libspeex -I$A/bt_audio_app_src/ai/speex
 -I$A/bt_audio_app_src/ai -I$A/bt_audio_app_src/inc -I$M/driver/driver_api/inc/otg -I$M/middleware/rtc/inc -I$M/middleware/fatfs/inc -I$M/middleware/user/inc -I$M/middleware/bluetooth/inc
 -I$M/middleware/audio/inc -I$M/driver/driver/inc -I$M/driver/driver_api/inc -I$M/middleware/mv_utils/inc -I$M/middleware/lrc/inc -I$M/middleware/rtos/rtos_api -I$M/middleware/rtos/freertos/inc
 -I$M/middleware/flashfs/inc -I$A/bt_audio_app_src/display -I$A/bt_audio_app_src/user -I$M/middleware/cec/inc -I$A/bt_audio_app_src/ble -I$A/bt_audio_app_src/libopus/include
 -I$A/bt_audio_app_src/libopus/silk -I$A/bt_audio_app_src/startup -I$M/startup"
FL="$ABI -Os -mcmodel=medium -mcpu=d1088-spu -mext-dsp -fsingle-precision-constant -ffunction-sections -fdata-sections -fcommon -fgnu89-inline -w -DFUNC_OS_EN=1 -DCFG_APP_CONFIG -DHAVE_CONFIG_H"
{ find "$A/bt_audio_app_src" -name '*.c' | grep -v -E 'sled_disp|seg_lcd_disp|[Ee]ncoder_servic|voice_app_demo_no_rtos|/ai/speex/|/libopus/'
  find "$M/middleware" "$M/driver/driver_api/src" -name '*.c'
  find "$M/startup" -maxdepth 1 -name '*.c' -newer /dev/null | grep -v -E 'init-default|interrupt|retarget'   # app has its own startup copies
} | sort -u > "$OUT/srcs.txt"
fail=0; n=0
while read -r f; do
  n=$((n+1)); o="$OUT/obj/$(echo "$f" | md5sum | cut -c1-8)_$(basename "$f" .c).o"
  nds32le-elf-gcc $FL $INC -c "$f" -o "$o" 2>"$OUT/err.tmp" || { fail=$((fail+1)); echo "FAIL $f: $(grep -m1 error "$OUT/err.tmp" | cut -c1-160)"; }
done < "$OUT/srcs.txt"
echo "compiled $((n-fail))/$n"
nds32le-elf-gcc $FL $INC -c "$A/bt_audio_app_src/startup/crt0.S" -o "$OUT/obj/crt0.o"
sed '102s/movi/li/' "$M/middleware/rtos/freertos/src/os_cpu_a.S" > "$OUT/os_cpu_a_fixed.S"; nds32le-elf-gcc $FL $INC -c "$OUT/os_cpu_a_fixed.S" -o "$OUT/obj/os_cpu_a.o"
SH=$(dirname "$(readlink -f "$0")")/../sdk-example
nds32le-elf-gcc $ABI -mcpu=d1088-spu -O2 -c "$SH/syscalls.c" -o "$OUT/obj/syscalls.o"
printf 'void _exit(int c){(void)c;for(;;);}\n' > "$OUT/exit.c"; nds32le-elf-gcc $ABI -c "$OUT/exit.c" -o "$OUT/obj/exit.o"
cat > "$OUT/dsp_stubs.c" <<'S'
/* PLACEHOLDER for Andes's proprietary libdsp (absent from the SDK): slow reference versions of the Q15/Q31 functions the app calls. */
#include <stdint.h>
#include <math.h>
int16_t nds32_sin_q15(int16_t x){ return (int16_t)lrintf(sinf((float)x*(3.14159265f/32768.0f))*32767.0f); }
int32_t nds32_sin_q31(int32_t x){ return (int32_t)lrint(sin((double)x*(3.14159265358979/2147483648.0))*2147483647.0); }
int32_t nds32_cos_q31(int32_t x){ return (int32_t)lrint(cos((double)x*(3.14159265358979/2147483648.0))*2147483647.0); }
int32_t nds32_sqrt_q31(int32_t x){ return x<=0?0:(int32_t)lrint(sqrt((double)x/2147483648.0)*2147483647.0); }
S
nds32le-elf-gcc $ABI -mcpu=d1088-spu -O2 -c "$OUT/dsp_stubs.c" -o "$OUT/obj/dsp_stubs.o"
L=""; for d in $M/driver/driver $M/middleware/audio $M/middleware/bluetooth $M/middleware/flashfs $M/middleware/fatfs $M/middleware/lrc $M/middleware/rtc $M/middleware/cec $M/middleware/xmai $A/bt_audio_app_src/libopus/lib; do L="$L -L$d"; done
nds32le-elf-gcc $ABI -Os -nostartfiles -static -mcmodel=medium -mext-dsp $L -T"$A/nds32-ae210p.ld" -Wl,--gc-sections -Wl,-Map="$OUT/app.map" \
  -o "$OUT/bt_audio_app.elf" "$OUT"/obj/*.o -lDriver -lsra -lcec -lsbcenc -lVocalCut -lmp3enc -lAudioEffectLibrary -lresampler -lAudioDecoderLibrary -lBtStack -lFlashFS -lLrc -lfatfs -lRTC -lcvsd_plc -lBlueAEC -lxmauth -lopus -lm -lc -lgcc > "$OUT/link.log" 2>&1
echo "link rc=$?"; grep -o "undefined reference to \`[^']*'" "$OUT/link.log" | sort | uniq -c | sort -rn | head -20
[ -f "$OUT/bt_audio_app.elf" ] && nds32le-elf-size "$OUT/bt_audio_app.elf" && nds32le-elf-objcopy -O binary "$OUT/bt_audio_app.elf" "$OUT/bt_audio_app.bin" && ls -l "$OUT/bt_audio_app.bin" | awk '{print "bin bytes:",$5}'
