NAME    = SMF Watchdog
DOC     = smfwatchdog.1
PREFIX ?= /opt/local
CFLAGS  = -Wall
SRC     = $(wildcard *.c)
BIN     = $(patsubst %.c,%,$(SRC))

all: $(BIN)

install: all
	cp -f $(BIN) $(PREFIX)/bin
	cp -f $(DOC) $(PREFIX)/man/man1

uninstall:
	cd $(PREFIX)/bin && rm -f $(BIN)
	rm -f $(PREFIX)/man/man1/$(DOC)

docs:
	@awk '/^```/ { flag=!flag; $$0 = "" } { if (flag) print "    " $$0; else print $$0; }' README.md | \
		ronn --manual '$(NAME)' --roff --pipe > $(DOC)

clean:
	rm -f $(BIN)

.PHONY: clean
