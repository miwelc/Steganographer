stegan: main.cpp steganography.cpp
	g++ -std=c++11 -O3 main.cpp steganography.cpp -lfreeimage -lcrypto -lm -o stegan

clean:
	rm stegan
