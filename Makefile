include /usr/local/etc/PcapPlusPlus.mk


# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -w -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o PktKrafter main.o  $(PCAPPP_LIBS)

# Clean Target
clean:
	rm main.o
	rm PktKrafter
