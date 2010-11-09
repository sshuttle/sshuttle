PANDOC:=$(shell \
	if pandoc </dev/null 2>/dev/null; then \
		echo pandoc; \
	else \
		echo "Warning: pandoc not installed; can't generate manpages." >&2; \
		echo '@echo Skipping: pandoc'; \
	fi)

default: all

all: sshuttle.8

sshuttle.8: sshuttle.md

%.8: %.md
	$(PANDOC) -s -r markdown -w man -o $@ $<

clean:
	rm -f *~ */*~ .*~ */.*~ *.8 *.tmp */*.tmp *.pyc */*.pyc
