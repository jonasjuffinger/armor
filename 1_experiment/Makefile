PWD := $(shell pwd)
DIR := $(shell basename $(PWD))

all: tar-source
	g++ main.cpp source.tar.gz.o -o main -larchive

tar-source:
	tar -czf source.tar.gz \
	    ../$(DIR)/*.cpp \
	    ../$(DIR)/*.h \
	    ../$(DIR)/Makefile \
	    ../common/*
	ld -r -b binary -o source.tar.gz.o source.tar.gz

clean:
	rm -f source.tar.gz *.o main
