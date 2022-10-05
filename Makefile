###############################
# ISA proj 1
# Autor: Tomáš Matuš
# Login: xmatus37
###############################

CXX=g++
CXXFLAGS=--std=c++11 -g -Wall -Wextra
LDLIBS=-lpcap
exec=flow
login=xmatus37
NAME=manual
SHELL=/usr/bin/env bash

all: $(exec)

pdf: 
	pdflatex $(NAME)
	pdflatex $(NAME)

#### flow
$(exec): flow.o netflowv5.o flow_cache.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDLIBS)

#### Object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^

#### MISC
clean:
	rm -f *.o $(exec)
	rm -f $(NAME).{aux,out,dvi,ps,log,te~,bcf,xml,pdf}

tar:
	tar -cf $(login).tar *.cpp Makefile README.md manual.pdf