DEBUG		=	0
CFLAGS 		=	-D__WIN8__ -Wall -Wextra
SOURCES		= 	$(wildcard *.c)
COMPILED	= 	$(SOURCES:.c=.o)
LINKED		= 	$(SOURCES:.c=.exe)
LDFLAGS		=	-lntdll -lpsapi -lktmw32 -lPwnLib-x64

CC		=	x86_64-w64-mingw32-gcc
INC		=	-I$(HOME)/code/pwnlib -I..
LIB		=	-L$(HOME)/code/pwnlib

CFLAGS		+=	-D__x86_64__ -I /usr/x86_64-w64-mingw32/include -D_WIN32_WINNT=0x0600


ifeq ($(DEBUG), 1)
CFLAGS		+=	-DDEBUG=1 -D_DEBUG=1 -g
endif


.PHONY : all clean

all: $(LINKED)

%.o : %.c
	@echo "[+] Compiling C file '$@'"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<


%.exe : %.o
	@echo "[+] Linking C file '$@'"
	$(CC) $(CFLAGS) -o $@ $? $(LIB) $(LDFLAGS)


clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(LINKED) $(COMPILED)