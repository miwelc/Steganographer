//
//  main.cpp
//  Steganographer
//
//  Created by Miguel Cantón Cortés in 2014
//

#include <iostream>
#include <fstream>
#include <cstring>
#include "steganography.h"

using namespace std;

int main(int argc, char *argv[]) {
	Steganography steg;
	ifstream in;
	ofstream out;
	unsigned char* buf = 0;
	char filename[256];
	size_t length;
	bool wrongParameters = false;
	bool sobel = false;
	
	if(argc < 5)
		wrongParameters = true;
	else if(argv[1][0] != '-' || argv[1][2] != '\0' || (argv[1][1] != 'i' && argv[1][1] != 'e'))
		wrongParameters = true;
	if(argc == 6) {
		if(argv[2][0] == '-' && argv[2][1] == 's' && argv[2][2] == '\0')
			sobel = true;
		else
			wrongParameters = true;
	}

	if(wrongParameters) {
		cout << "Wrong parameters.\n";
		cout << "Insertion:\tstegan -i [-s] inputImg messageFile password\n";
		cout << "Extraction:\tstegan -e [-s] inputImg outputFile password\n";
		exit(-1);
	}
	
	int offset = (argc == 6 ? 1 : 0);
	if(argv[1][1] == 'i') {
		in.open(argv[3+offset], ios::binary);
		in.seekg(0, ios::end);
		length = in.tellg();
		in.seekg(0, ios::beg);
		if(length == (size_t)-1) {
			cout << "File '" << argv[3+offset] << "' not found\n";
			return -1;
		}
		buf = new unsigned char[length];
		in.read((char*)buf, length);
		in.close();
		
		if(sobel)
			cout << "Inserting using Sobel mode\n";
		else
			cout << "Inserting using normal mode\n";
		
		steg.loadImage(argv[2+offset]);
		if(steg.embed((unsigned char*)argv[4+offset], strlen(argv[4+offset]), buf, length, sobel)) {
			argv[2+offset][strlen(argv[2+offset])-4] = '\0';
			snprintf(filename, 256, "cod_%s.png", argv[2+offset]);
			steg.saveImage(filename, FIF_PNG);
			cout << "File inserted correctly\n";
		}
		else {
			if(buf)
				delete [] buf;
			return 1;
		}
	}
	else if(argv[1][1] == 'e') {
		steg.loadImage(argv[2+offset]);
		
		if(sobel)
			cout << "Extracting using Sobel mode\n";
		else
			cout << "Extracting using normal mode\n";
		
		if(steg.extract((unsigned char*)argv[4+offset], strlen(argv[4+offset]), &buf, &length, sobel)) {
			out.open(argv[3+offset], ios::binary);
			out.write((char*)buf, length);
			out.close();
			cout << "File extracted correctly\n";
		}
		else {
			cout << "Nothing extracted\n";
			if(buf)
				delete [] buf;
			return 2;
		}
	}
	
	if(buf)
		delete [] buf;
	
	return 0;
}
