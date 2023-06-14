LDLIBS=-lpcap

all: deauth-attack

deauth-attack: main.o mac.o dot11.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f *.o deauth-attack