# Target programs
programs := \
        simple_writer.x \
        simple_reader.x \
        test_fs.x

# File-system library
FSLIB := libfs
FSPATH := ../$(FSLIB)
libfs := $(FSPATH)/$(FSLIB).a

# Default rule
all: $(programs)

# Avoid builtin rules and variables
MAKEFLAGS += -rR

# Don't print commands unless `make V=1`
ifneq ($(V),1)
Q = @
V = 0
endif

# Current directory
CUR_PWD := $(shell pwd)

# Compiler
CC = gcc

# CFLAGS for user code (with -Werror)
CFLAGS := -Wall -Werror -pipe
ifneq ($(D),1)
CFLAGS += -O2
else
CFLAGS += -g
endif
CFLAGS += -I$(FSPATH)

# For test_fs.c only: drop -Werror, disable format warnings
TESTFLAGS := $(filter-out -Werror,$(CFLAGS)) -Wno-format

# Linker flags
LDFLAGS := -L$(FSPATH) -lfs

# Object files
objs := simple_writer.o simple_reader.o test_fs.o

# Build libfs.a if needed
$(libfs): FORCE
	@echo "MAKE    $@"
	$(Q)$(MAKE) V=$(V) D=$(D) -C $(FSPATH)

# Link final executables
simple_writer.x: simple_writer.o $(libfs)
	@echo "LD      $@"
	$(Q)$(CC) -o $@ simple_writer.o $(LDFLAGS)

simple_reader.x: simple_reader.o $(libfs)
	@echo "LD      $@"
	$(Q)$(CC) -o $@ simple_reader.o $(LDFLAGS)

test_fs.x: test_fs.o $(libfs)
	@echo "LD      $@"
	$(Q)$(CC) -o $@ test_fs.o $(LDFLAGS)

# Compile object files (omit fs.h and disk.h from deps to avoid missing-header errors)
simple_writer.o: simple_writer.c
	@echo "CC      simple_writer.o"
	$(Q)$(CC) $(CFLAGS) -c simple_writer.c -o simple_writer.o

simple_reader.o: simple_reader.c
	@echo "CC      simple_reader.o"
	$(Q)$(CC) $(CFLAGS) -c simple_reader.c -o simple_reader.o

test_fs.o: test_fs.c
	@echo "CC      test_fs.o"
	$(Q)$(CC) $(TESTFLAGS) -c test_fs.c -o test_fs.o

# Clean
clean: FORCE
	@echo "CLEAN   $(CUR_PWD)"
	$(Q)$(MAKE) V=$(V) D=$(D) -C $(FSPATH) clean
	$(Q)rm -f $(objs) $(programs)

.PHONY: FORCE
FORCE:
