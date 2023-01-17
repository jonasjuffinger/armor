PWD := $(shell pwd)
DIR := $(shell basename $(PWD))
BASEDIR := $(shell dirname $(PWD))

all: tar-source install-libarchive
	g++-10 main.cpp source.tar.gz.o -O3 -Wall -Wno-unused-function -Wno-strict-aliasing -std=c++2a -o main -larchive

tar-source:
	tar -czf source.tar.gz ../$(DIR)/*.cpp ../$(DIR)/*.h ../$(DIR)/Makefile ../common/*
	ld -r -b binary -o source.tar.gz.o source.tar.gz

install-libarchive:
	@if ! ldconfig -p | grep libarchive; then \
		if which apt 1>&2 2> /dev/null; then \
		  echo Installing libarchive-dev; \
			sudo apt install libarchive-dev; \
		else \
			echo ERROR: Please install libarchive-dev!; \
			exit 1; \
		fi \
	fi

clean:
	rm -f source.tar.gz *.o main