//
//  steganography.h
//  Steganographer
//
//  Created by Miguel Cantón Cortés in 2014
//

#ifndef _Steganography_H_
#define _Steganography_H_

#include <FreeImage.h>

class Steganography {
	private:
		FIBITMAP* image;
		uint8_t* sobelImg;
		unsigned height;
		unsigned width;
		size_t totalPixels;
		struct Header {
			size_t lengthUncompressed;
			size_t lengthEncrypted;
			uint8_t iv[32];
		};
		void getSHA256(const uint8_t* data, size_t length, uint8_t* hash);
		void zlibCompress(uint8_t* in, size_t lengthIn, uint8_t** out, size_t* lengthOut);
		void zlibUncompress(uint8_t* in, size_t lengthIn, uint8_t** out, size_t lengthOut);
		void aesEncrypt(const uint8_t* data, size_t dataLen, uint8_t** encr, size_t* len,
						const uint8_t* key_data, unsigned key_data_length, uint8_t* iv);
		void aesDecrypt(const uint8_t* encr, size_t encrLen, uint8_t** data, size_t* dataLen,
						const uint8_t* key_data, unsigned key_data_length, const uint8_t* iv);
		uint8_t applySobelFilter(unsigned x, unsigned y);
		bool changesSobel(long x, long y, uint8_t rgb);
		uint8_t readBit(unsigned x, unsigned y, uint8_t rgb);
		void writeBit(unsigned x, unsigned y, uint8_t rgb, uint8_t bit);

	public:
		Steganography();
		~Steganography();
		void loadImage(const char* file);
		void saveImage(const char* file, FREE_IMAGE_FORMAT format, int flags = 0);
		bool embed(const uint8_t* key, unsigned keyLength, uint8_t* data, size_t length, bool sobelMode = false);
		bool extract(const uint8_t* key, unsigned keyLength, uint8_t** data, size_t* length, bool sobelMode = false);
};

#endif
