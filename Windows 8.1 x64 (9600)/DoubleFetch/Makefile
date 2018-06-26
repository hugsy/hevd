DEBUG		=	0
CFLAGS 		=	-D__WIN81__ -Wall -Wextra
SOURCES		= 	$(wildcard *.c)
COMPILED	= 	$(SOURCES:.c=.o)
LINKED		= 	$(SOURCES:.c=.exe)
LDFLAGS		=	-lntdll -lPwnLib-x64 -lpsapi

CC		=	x86_64-w64-mingw32-gcc
INC		=	-I$(HOME)/code/pwnlib -I..
LIB		=	-L$(HOME)/code/pwnlib

CFLAGS		+=	-D__x86_64__ -I /usr/x86_64-w64-mingw32/include -D_WIN32_WINNT=0x0600


ifeq ($(DEBUG), 1)
CFLAGS		+=	-DDEBUG=1 -D_DEBUG=1 -g
endif


.PHONY : all clean doublefetch

all: clean doublefetch

%.o : %.c
	@echo "[+] Compiling C file '$@'"
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<


%.exe : %.o
	@echo "[+] Linking C file '$@'"
	$(CC) $(CFLAGS) -o $@ $? $(LIB) $(LDFLAGS)


doublefetch: exploit.exe
	cp $< ~/tmp/$@.exe


clean :
	@echo "[+] Cleaning stuff"
	@rm -f $(LINKED) $(COMPILED)