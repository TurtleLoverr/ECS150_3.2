# Target library
lib := libfs.a

# Compiler and tools
CC = gcc
AR = ar

# Common flags (no -Werror here)
CFLAGS   = -Wall -Wextra -std=gnu99 -g
# Additional flags for fs.c (enable -Werror)
FSFLAGS  = $(CFLAGS) -Werror

# Archive flags
ARFLAGS = rcs

# Object files
objs = fs.o disk.o

all: $(lib)

# Compile fs.c with -Werror
fs.o: fs.c fs.h disk.h
	$(CC) $(FSFLAGS) -c fs.c -o fs.o

# Compile disk.c without -Werror, disable only the format warning
disk.o: disk.c disk.h
	$(CC) $(CFLAGS) -Wno-format -c disk.c -o disk.o

# Archive the static library
$(lib): $(objs)
	$(AR) $(ARFLAGS) $@ $^

# Cleaning rule
clean:
	rm -f *.o $(lib)
