//
//  steganography.cpp
//  Steganographer
//
//  Created by Miguel Cantón Cortés in 2014
//

#include <cstdlib>
#include <cstring>
#include <cmath>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <random>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <sstream>
#include <vector>
#include <unordered_set>

#include "steganography.h"

using namespace std;

Steganography::Steganography() {
	width = height = 0;
	totalPixels = 0;
	image = 0;
	sobelImg = 0;
	FreeImage_Initialise();
}

Steganography::~Steganography() {
	if(image)
		FreeImage_Unload(image);
	if(sobelImg)
		delete [] sobelImg;
	FreeImage_DeInitialise();
}

void Steganography::getSHA256(const uint8_t* data, size_t length, uint8_t* hash) {
    SHA256_CTX sha256;
	
    SHA256_Init(&sha256);
	SHA256_Update(&sha256, data, length);
    SHA256_Final(hash, &sha256);
}

void Steganography::zlibCompress(uint8_t* in, size_t lengthIn, uint8_t** out, size_t* lengthOut) {
	size_t maxSize = (size_t)((double)lengthIn + (0.1 * (double)lengthIn) + 12);
	*out = new uint8_t[maxSize];
	*lengthOut = FreeImage_ZLibCompress(*out, maxSize, in, lengthIn);
}

void Steganography::zlibUncompress(uint8_t* in, size_t lengthIn, uint8_t** out, size_t lengthOut) {
	*out = new uint8_t[lengthOut];
	FreeImage_ZLibUncompress(*out, lengthOut, in, lengthIn);
}

void Steganography::aesEncrypt(const uint8_t* data, size_t dataLen, uint8_t** encr, size_t* len,
							   const uint8_t* key_data, unsigned key_data_length, uint8_t* iv) {
	int written = 0;
	size_t total = 0;
	EVP_CIPHER_CTX e_ctx;
	uint8_t key[32];
	
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_length, 5, key, iv);
	EVP_CIPHER_CTX_init(&e_ctx);
	EVP_EncryptInit_ex(&e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	*encr = new uint8_t[dataLen + AES_BLOCK_SIZE];
	
	for(size_t i = 0; i < dataLen; i += 2048) {
		int toRead = (dataLen-i > 2048 ? 2048 : dataLen-i);
		EVP_EncryptUpdate(&e_ctx, *encr+total, &written, &data[i], toRead);
		total += written;
	}
	EVP_EncryptFinal_ex(&e_ctx, *encr+total, &written);
	*len = total + written;
}


void Steganography::aesDecrypt(const uint8_t* encr, size_t encrLen, uint8_t** data, size_t* dataLen,
							   const uint8_t* key_data, unsigned key_data_length, const uint8_t* iv) {
	int written = 0;
	size_t total = 0;
	EVP_CIPHER_CTX d_ctx;
	uint8_t key[32], foo[32];
	
	EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, key_data, key_data_length, 5, key, foo);
	EVP_CIPHER_CTX_init(&d_ctx);
	EVP_DecryptInit_ex(&d_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	
	*data = new uint8_t[encrLen + AES_BLOCK_SIZE];
	
	for(size_t i = 0; i < encrLen; i += 2048) {
		int toRead = (encrLen-i > 2048 ? 2048 : encrLen-i);
		EVP_DecryptUpdate(&d_ctx, *data+total, &written, &encr[i], toRead);
		total += written;
	}
	EVP_DecryptFinal_ex(&d_ctx, *data+total, &written);
	*dataLen = total + written;
}

uint8_t Steganography::applySobelFilter(unsigned x, unsigned y) {
	const short dx[3][3] = {{1,0,-1}, {2,0,-2}, {1,0,-1}};
	const short dy[3][3] = {{1,2,1}, {0,0,0}, {-1,-2,-1}};
	
	if(x == 0 || x >= width-1 || y == 0 || y >= height-1)
		return 0;
	
	RGBQUAD color;
	int sumX = 0, sumY = 0;
	for(int m = -1; m <= 1; m++) {
		for(int n = -1; n <= 1; n++) {
			FreeImage_GetPixelColor(image, x+n, y+m, &color);
			//int grey = 0.2126*color.rgbRed + 0.7152*color.rgbGreen + 0.0722*color.rgbBlue;
			int grey = (color.rgbRed+color.rgbGreen+color.rgbBlue)/3;
			sumX += grey * dx[m+1][n+1];
			sumY += grey * dy[m+1][n+1];
		}
	}
	//return sqrt(sumX*sumX + sumY*sumY) > 140 ? 255 : 0;
	return abs(sumX)+abs(sumY) > 160 ? 255 : 0;
}

bool Steganography::changesSobel(long x, long y, uint8_t rgb) {
	bool changed = false;
	
	uint8_t oldBit = readBit(x, y, rgb);
	
	writeBit(x, y, rgb, !oldBit);
	for(long i = x-1; i <= x+1 && i < width && !changed; i++)
		for(long j = y-1; j <= y+1 && j < height && !changed; j++)
			if(i>=0 && j>=0 && applySobelFilter(i, j) != sobelImg[i+j*width])
				changed = true;
	
	writeBit(x, y, rgb, oldBit);
	
	return changed;
}

uint8_t Steganography::readBit(unsigned x, unsigned y, uint8_t rgb) {
	RGBQUAD color;
	FreeImage_GetPixelColor(image, x, y, &color);
	switch(rgb) {
		case 0: return color.rgbRed & 0x01; break;
		case 1: return color.rgbGreen & 0x01; break;
		case 2: return color.rgbBlue & 0x01; break;
		default: return 0;
	}
}

void Steganography::writeBit(unsigned x, unsigned y, uint8_t rgb, uint8_t bit) {
	RGBQUAD color;
	FreeImage_GetPixelColor(image, x, y, &color);
	switch(rgb) {
		case 0:
			if(bit) color.rgbRed |= 0x01;
			else color.rgbRed &= 0xFE;
			break;
		case 1:
			if(bit) color.rgbGreen |= 0x01;
			else color.rgbGreen &= 0xFE;
			break;
		case 2:
			if(bit) color.rgbBlue |= 0x01;
			else color.rgbBlue &= 0xFE;
			break;
		default: break;
	}
	FreeImage_SetPixelColor(image, x, y, &color);
}

void Steganography::loadImage(const char* file) {
	if(image)
		FreeImage_Unload(image);
	if(sobelImg)
		delete [] sobelImg;

	image = FreeImage_Load(FreeImage_GetFileType(file), file);
	FreeImage_ConvertTo24Bits(image);
	width = FreeImage_GetWidth(image);
	height = FreeImage_GetHeight(image);
	totalPixels = width*height;
	
	FIBITMAP* bitmap = FreeImage_Allocate(width, height, 8);
	sobelImg = new uint8_t[totalPixels];
	for(unsigned x = 0; x < width; x++) {
		for(unsigned y = 0; y < height; y++) {
			uint8_t value = applySobelFilter(x, y);
			sobelImg[x+y*width] = value;
			FreeImage_SetPixelIndex(bitmap, x, y, &value);
		}
	}
	FreeImage_Save(FIF_PNG, bitmap, "sobel.png");
	FreeImage_Unload(bitmap);
}

void Steganography::saveImage(const char* file, FREE_IMAGE_FORMAT format, int flags) {
	FreeImage_Save(format, image, file, flags);
}

bool Steganography::embed(const uint8_t* key, unsigned keyLength, uint8_t* data, size_t length, bool sobelMode) {
	uint8_t hash[SHA256_DIGEST_LENGTH];
	Header header;
	uint8_t *compressedData=0, *encryptedData=0;
	size_t lengthCompressed = 0;
	vector<size_t> listCandidates;
	unordered_set<size_t> chosen;
	
	if(height == 0 || width == 0) {
		cout << "Cannot insert: no image loaded\n";
		return false;
	}
	if(length == 0) {
		cout << "Cannot insert: no message\n";
		return false;
	}
	
	getSHA256(key, keyLength, hash);
	
	header.lengthUncompressed = length;
	zlibCompress(data, length, &compressedData, &lengthCompressed);
	
	aesEncrypt(compressedData, lengthCompressed, &encryptedData, &header.lengthEncrypted,
			   key, keyLength, header.iv);
	
	delete [] compressedData;
	
	listCandidates.reserve(totalPixels);
	for(size_t i = 0; i < totalPixels; i++) {
		if(sobelMode == false || sobelImg[i] == 255) {
			listCandidates.push_back(i);
		}
	}
	
	cout << "Message size:\n";
	cout << "\tUncompressed:\t" << length << " bytes\n";
	cout << "\tCompressed:\t" << lengthCompressed << " bytes\n";
	cout << "\tEncrypted:\t" << header.lengthEncrypted << " bytes\n";
	if(!sobelMode)
		cout << "The maximum size for this image is: " << totalPixels/8-sizeof(Header)
			<< " bytes\n";
	
	//Seed generators using hash(key)
	seed_seq seed1(hash, hash+16);
	seed_seq seed2(hash+16, hash+32);
	
	shuffle(listCandidates.begin(), listCandidates.end(), std::mt19937(seed1));
	
	std::uniform_int_distribution<int> distribution2(0,2);
	std::mt19937 generator2(seed2);
	auto diceRGB = std::bind(distribution2, generator2);

	size_t position = 0, nBytesToWrite = sizeof(Header) + header.lengthEncrypted;
	uint8_t byte;
	long x, y;
	for(size_t i = 0; i < nBytesToWrite; i++) {
		if(i < sizeof(Header))
			byte = ((uint8_t*)&header)[i];
		else
			byte = encryptedData[i-sizeof(Header)];
		
		for(unsigned bit = 0; bit < 8; bit++) {
			uint8_t rgb = diceRGB();
			bool valid;
			do {
				if(++position >= listCandidates.size()) { //No space
					cout << "Cannot insert: file is too big\n";
					delete [] encryptedData;
					return false;
				}
				x = listCandidates[position]%width;
				y = listCandidates[position]/width;
				valid = true;
				if(sobelMode) {
					valid = !changesSobel(x, y, rgb);
					if(valid) {
						for(long i = x-2; i <= x+2 && valid; i++)
							for(long j = y-2; j <= y+2 && valid; j++)
								if(i>=0 && j>=0 && i < width && j < height)
									if(chosen.find(i+j*width) != chosen.end())
										valid = false;
					}
					chosen.insert(x+y*width);
				}
			} while(valid == false);
			
			writeBit(x, y, rgb, (byte>>bit)&0x01);
		}
	}
	
	delete [] encryptedData;
	
	return true;
}

bool Steganography::extract(const uint8_t* key, unsigned keyLength, uint8_t** data, size_t* length, bool sobelMode) {
	uint8_t hash[SHA256_DIGEST_LENGTH];
	Header header;
	uint8_t *compressedData=0, *encryptedData=0;
	size_t lengthCompressed = 0;
	vector<size_t> listCandidates;
	unordered_set<size_t> chosen;
	
	if(height == 0 || width == 0) {
		cout << "Cannot extract: no image loaded\n";
		*data = 0;
		*length = 0;
		return false;
	}
	
	getSHA256(key, keyLength, hash);
	
	listCandidates.reserve(totalPixels);
	for(size_t i = 0; i < totalPixels; i++) {
		if(sobelMode == false || sobelImg[i] == 255) {
			listCandidates.push_back(i);
		}
	}
	
	//Seed generators using hash(key)
	seed_seq seed1(hash, hash+16);
	seed_seq seed2(hash+16, hash+32);
	
	shuffle(listCandidates.begin(), listCandidates.end(), std::mt19937(seed1));
	
	std::uniform_int_distribution<int> distribution2(0,2);
	std::mt19937 generator2(seed2);
	auto diceRGB = std::bind(distribution2, generator2);
	
	size_t position = 0, nBytesToRead = sizeof(Header);
	uint8_t byte;
	long x, y;
	for(size_t i = 0; i < nBytesToRead; i++) {
		for(unsigned bit = 0; bit < 8; bit++) {
			uint8_t rgb = diceRGB();
			bool valid;
			do {
				if(++position >= listCandidates.size()) { //No space
					*data = 0;
					*length = 0;
					if(encryptedData)
						delete [] encryptedData;
					return false;
				}
				x = listCandidates[position]%width;
				y = listCandidates[position]/width;
				valid = true;
				if(sobelMode) {
					valid = !changesSobel(x, y, rgb);
					if(valid) {
						for(long i = x-2; i <= x+2 && valid; i++)
							for(long j = y-2; j <= y+2 && valid; j++)
								if(i>=0 && j>=0 && i < width && j < height)
									if(chosen.find(i+j*width) != chosen.end())
										valid = false;
					}
					chosen.insert(x+y*width);
				}
			} while(valid == false);
			
			if(readBit(x, y, rgb))
				byte |= (1<<bit);
			else
				byte &= ~(1<<bit);
		}
		if(i < sizeof(Header)) {
			((uint8_t*)&header)[i] = byte;
			if(i == sizeof(Header)-1) {
				nBytesToRead = sizeof(Header) + header.lengthEncrypted;
				if(nBytesToRead*8 > totalPixels) { // No sense
					*data = 0;
					*length = 0;
					return false;
				}
				encryptedData = new uint8_t[header.lengthEncrypted];
			}
		}
		else
			encryptedData[i-sizeof(Header)] = byte;
	}
	
	aesDecrypt(encryptedData, header.lengthEncrypted, &compressedData, &lengthCompressed, key, keyLength, header.iv);
	delete [] encryptedData;
	
	zlibUncompress(compressedData, lengthCompressed, data, header.lengthUncompressed);
	*length = header.lengthUncompressed;
	
	delete [] compressedData;
	
	return true;
}




