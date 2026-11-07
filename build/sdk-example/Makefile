# Build MVsilicon SDK example (default: Example_GPIO) with upstream GCC 13 nds32le-elf.
# Mirrors the flags in the SDK's generated Eclipse makefile (Debug/subdir.mk, Debug/makefile).
#   make SDK=/path/to/bp1048_sdk_v0.1.12 TC=/path/to/prefix-le OUT=/path/to/out [EX=Example_GPIO]
SDK  ?= /home/user/leadercxn/bp1048_sdk_v0.1.12
TC   ?= $(CURDIR)/toolchain
OUT  ?= $(CURDIR)/out
EX   ?= Example_GPIO
BASE := $(SDK)/MVsB1_Base_SDK
EXD  := $(BASE)/examples/$(EX)
HERE := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
CC   := $(TC)/bin/nds32le-elf-gcc
OBJCOPY := $(TC)/bin/nds32le-elf-objcopy
SIZE := $(TC)/bin/nds32le-elf-size

INC := -I$(BASE)/driver/driver/inc -I$(BASE)/driver/driver_api/inc -I$(BASE)/middleware/mv_utils/inc
# SDK flags: -Og -mcmodel=medium -g3 -Wall -mcpu=d1088-spu -mext-dsp -mext-zol -fsingle-precision-constant ...
# -ldsp / -mvh / -mext-zol are Andes-fork options; EXTRA lets us drop the ones upstream GCC rejects.
EXTRA ?=
ABI := -mabi=2fp+ -mext-fpu-sp -mconfig-fpu=2
CFLAGS := $(ABI) -Og -mcmodel=medium -g3 -Wall -mcpu=d1088-spu -mext-dsp -fsingle-precision-constant \
          -ffunction-sections -fdata-sections -fmessage-length=0 -fcommon $(EXTRA)

SRCS := $(BASE)/startup/crt0.S $(BASE)/startup/init-default.c $(BASE)/startup/interrupt.c \
        $(BASE)/startup/retarget.c $(BASE)/driver/driver_api/src/uarts_interface.c $(wildcard $(EXD)/src/*.c) $(HERE)/syscalls.c
OBJS := $(patsubst %,$(OUT)/%.o,$(notdir $(SRCS)))

all: $(OUT)/$(EX).bin
$(OUT)/%.c.o: ; @mkdir -p $(OUT)
$(OUT)/crt0.S.o: $(BASE)/startup/crt0.S ; @mkdir -p $(OUT); $(CC) $(INC) $(CFLAGS) -c -o $@ $<
define RULE
$(OUT)/$(notdir $(1)).o: $(1) ; @mkdir -p $(OUT); $(CC) $(INC) $(CFLAGS) -c -o $$@ $$<
endef
$(foreach s,$(filter %.c,$(SRCS)),$(eval $(call RULE,$(s))))
$(OUT)/$(EX).adx: $(OBJS) $(EXD)/nds32-ae210p.ld
	$(CC) -Og -nostartfiles -static -L$(BASE)/driver/driver -mcmodel=medium -mext-dsp -T$(EXD)/nds32-ae210p.ld \
	   $(ABI) -Wl,--gc-sections -o $@ $(OBJS) -lDriver $(LDEXTRA)
$(OUT)/$(EX).bin: $(OUT)/$(EX).adx ; $(OBJCOPY) -S -O binary $< $@ ; $(SIZE) $<
clean: ; rm -rf $(OUT)
.PHONY: all clean
