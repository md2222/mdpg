#!/bin/make
#Makefile curl1

SOURCES = main.c crypto_scrypt-nosse.c sha256.c base91.c
#crypto_scrypt-sse.c

CFLAGS  = `pkg-config --cflags gtk+-3.0`
#CFLAGS += -I../../api/

LIBS    = `pkg-config --libs gtk+-3.0 libcrypto`
#LIBS    += -I/usr/include/webkitgtk-4.0 

TARGET  = mdpg


all:
	gcc $(CFLAGS) $(SOURCES) -o $(TARGET) $(LIBS)
	

PREFIX=/usr/local

install: mdpg
#	which mdpg && { echo ! mdpg already installed, first uninstall old version; exit 1; }  || echo installing...
	
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/mdpg"
	cp -i -- mdpg "$(DESTDIR)$(PREFIX)/bin/"
	cp -i -- mainWin.glade "$(DESTDIR)$(PREFIX)/share/mdpg/"
	
	
uninstall:
	-rm -- "$(DESTDIR)$(PREFIX)/bin/mdpg"
	-rm -r -- "$(DESTDIR)$(PREFIX)/share/mdpg"
	
	
clean:
	-rm -f -- *.o mdpg	

.PHONY: all install uninstall clean
