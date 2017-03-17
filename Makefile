CC              = gcc
LD              = gcc
AR              = ar

CFLAGS          = -Wall -ansi 
LFLAGS          = -Wall -ansi

SENDEROBJS		= sender.o gbn.o
RECEIVEROBJS	= receiver.o gbn.o
ALLEXEC			= sender receiver

.c.o:
	$(CC) $(CFLAGS) -c $<

all: $(ALLEXEC)

sender: $(SENDEROBJS)
	$(LD) $(LFLAGS) -o $@ $(SENDEROBJS)

receiver: $(RECEIVEROBJS)
	$(LD) $(LFLAGS) -o $@ $(RECEIVEROBJS)

clean:
	rm -f *.o $(ALLEXEC)

realclean: clean
	rm -rf proj1.tar.gz

tarball: realclean
	tar cf - `ls -a | grep -v '^\.*$$' | grep -v '^proj[0-9].*\.tar\.gz'` | gzip > proj1-$(USER).tar.gz
