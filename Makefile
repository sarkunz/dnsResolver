#
# Student makefile for DNS resolver lab
# Note: requires a 64-bit x86-64 system 
#
CC = gcc
CFLAGS = -g -std=c11

all: resolver

resolver: resolver.c
	$(CC) $(CFLAGS) -o resolver resolver.c -lm 

test:
	./autograde-dnsresolver.py

clean:
	rm -f resolver
