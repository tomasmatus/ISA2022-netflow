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
FILES=*.cpp *.hpp Makefile manual.pdf flow.1 README.md

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
	rm -f $(NAME).{aux,out,dvi,ps,log,te~,bcf,xml}

eva: zip
	scp $(login).zip $(login)@eva.fit.vutbr.cz:~/isa

tar:
	tar -cf $(login).tar $(FILES)

zip:
	zip $(login).zip $(FILES)
