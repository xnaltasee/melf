CC       = gcc
CFLAGS   = -std=c99 -Wall -Wextra -Wpedantic -Wstrict-prototypes

FILE_IN  = melf.c
FILE_OUT = melf

melf:
	$(CC) $(CFLAGS) $(FILE_IN) -o $(FILE_OUT)

clean:
	$(RM) $(FILE_OUT)
