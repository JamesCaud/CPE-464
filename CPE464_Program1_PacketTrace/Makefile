# Makefile for Program 1 - Trace
# By: James Caudill

CC = gcc
CFLAGS = -g -Wall 

all:  trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c  -lpcap 

clean:
	rm -f trace
