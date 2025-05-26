# Target library
lib := libfs.a

all: $(lib)

## TODO: Phase 1

# Variables
CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -Werror -g
ARFLAGS = rcs
objs = fs.o disk.o


# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Archive the static library
$(lib): $(objs)
	$(AR) $(ARFLAGS) $@ $^

# Cleaning rule
clean:
	rm -rf *.o