/***********************************************************************************************

		partialEncrypt.c

		Discription		:	Encrypt / Decrypt the specific area of the file using RSA algorithm.
		Purpose			:	1) Providing a high level of security.
							2) Improvement speed of the conventional RSA algorithm.
		Requirements	:	Openssl library to be installed.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
#pragma warning(disable : 4996)
#pragma once

#include "partialEncrypt.h"

/***********************************************************************************************

		Module Name		:	encFileOne
		Function		:	Encrypt an area of the file.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int Encrypt(RSA* PRk, RSA* PUk, char* fileName)
{
	//In/Ouput file pointer
	FILE * in;
	FILE * out;
	int fileSize, remainLen;

	//Variables for generate encrypt area.
	int offset, blockSize;

	int enced_len;
	int result;

	unsigned char plain_text[246];			//plain text buffer
	unsigned char plain_header[246];		//plain header buffer
	unsigned char cipher_header[256];		//cipher header buffer
	unsigned char cipher_text[256];			//cipher text buffer

	char buf[1024];
	char * extention;

	//Open target file and create encryted file.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");
	
	//Get target file's extention.
	extention = strtok(fileName, ".");
	extention = strtok(NULL, ".");
	
	//Get target file's file size.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//Generate block Size and start offset using file Size.
	blockSize = 122 + (rand() % 122);
	offset = 122 + (rand() % (fileSize - 122));
	offset -= blockSize;

	//Create header.
	sprintf(plain_header, "1|%s|%d|%d|%d", extention, fileSize, offset, blockSize);

	//Encrypt header for receiver's public key(Header decryption is avalilable only to the receiver).
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);

	//Move the file pointer to the front.
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//Write encrypted header into the file.
	result = fwrite(cipher_header, 256, 1, out); if (result == -1) return -1;
	
	//The remaining length until to be encrypted.
	remainLen = offset - ftell(in);

	//Writes the plain text before encrypting area.
	while (remainLen != 0)
	{
		if (remainLen >= 1024)
		{
			//if remained plain text is bigger than plain buffer size(1024).
			result = fread(buf, 1, 1024, in); if (result == -1) return -1;
			result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
		}
		else
		{
			//if remained plain text is less than plain buffer size(1024).
			result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
			result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
		}
		remainLen = offset - ftell(in);

	}

	//Read encrypt area from target file.
	result = fread(plain_text, 1, blockSize, in); if (result == -1) return -1;
	//Encrypt area.
	enced_len = RSA_private_encrypt(blockSize, plain_text, cipher_text, PRk, RSA_PKCS1_PADDING);
	//Write cipher text.
	result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;

	//Write remain plain text.
	while (!feof(in))
	{
		result = fread(buf, 1, 1024, in); if (result == -1) return -1;
		result = fwrite(buf, 1, result, out); if (result == -1) return -1;
	}

	//End file read/write.
	fclose(in);
	fclose(out);

	return blockSize;
};

/***********************************************************************************************

		Module Name		:	encFileTen
		Function		:	Encrypt some area of the file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int partEncrypt(RSA* PRk, RSA* PUk, char* fileName, int areaCount)
{
	//In/Ouput file pointer
	FILE * in;
	FILE * out;
	int fileSize, remainLen;

	//Variables for generate encrypt area.
	int offset[10] = { 0 };
	int blockSize[10] = { 0 };

	int enced_len;
	int result;

	int total_enc_len = 0;
	int remain_area_len = 0;

	unsigned char plain_text[246];			//plain text buffer
	unsigned char plain_header[246];		//plain header buffer

	unsigned char cipher_header[256];		//cipher header buffer
	unsigned char cipher_text[256];			//cipher text buffer

	unsigned char temp_header[100];		//temparay buffer for save header information.

	char buf[1024];
	char * extention;

	//Open target file and create encryted file.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");

	//Get target file's extention.
	extention = strtok(fileName, ".");
	extention = strtok(NULL, ".");

	//Get target file's file size.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//Wrtie encrypt area count.
	sprintf(plain_header, "%d|%s|%d", areaCount, extention, fileSize);

	//loop area count
	for (int i = 0; i < areaCount; i++)	{
		//Generate block Size and start offset using (file Size / areaCount).
		
		if (i == (areaCount - 1))	{
			blockSize[i] = (rand() % ((fileSize / areaCount) + (fileSize % areaCount)));

			if (blockSize[i] > 245)	blockSize[i] = (blockSize[i] % 245);

			offset[i] = (rand() % (((fileSize / areaCount) + (fileSize % areaCount)) - blockSize[i]));
		}
		else if (i == 0)
		{
			//Encrypt file header
			blockSize[i] = 245;
			offset[i] = 0;
		}
		else
		{
			blockSize[i] = (rand() % (fileSize / areaCount));

			if (blockSize[i] > 245)	blockSize[i] = (blockSize[i] % 245);

			offset[i] = (rand() % ((fileSize / areaCount) - blockSize[i]));
		}

		//Create header.
		sprintf(temp_header, "|%d|%d", offset[i], blockSize[i]);
		strcat(plain_header, temp_header);
	}

	//Encrypt header for receiver's public key(Header decryption is avalilable only to the receiver).
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);

	//Move the file pointer to the front.
	result = fseek(in, 0, SEEK_SET);
	if (result == -1) return -1;

	result = fseek(out, 0, SEEK_SET);
	if (result == -1) return -1;

	//Write encrypted header into the file.
	result = fwrite(cipher_header, 256, 1, out);
	if (result == -1) return -1;

	for (int i = 0; i < areaCount; i++)	{
		//The remaining length until to be encrypted.
		remainLen = (((fileSize / areaCount) * i) + offset[i]) - ftell(in);

		//Writes the plain text before encrypting area.
		while (remainLen != 0)
		{
			if (remainLen >= 1024)
			{
				//if remained plain text is bigger than plain buffer size(1024).
				result = fread(buf, 1, 1024, in); if (result == -1) return -1;
				result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
			}
			else
			{
				//if remained plain text is less than plain buffer size(1024).
				result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
				result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
			}

			remainLen = (((fileSize / areaCount) * i) + offset[i]) - ftell(in);
		}

		//Read encrypt area from target file.
		result = fread(plain_text, 1, blockSize[i], in); if (result == -1) return -1;
		//Encrypt area.
		enced_len = RSA_private_encrypt(blockSize[i], plain_text, cipher_text, PRk, RSA_PKCS1_PADDING);
		//Write cipher text.
		result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;

		total_enc_len += enced_len;

		//The remaining length after encrypt area.
		if (i == (areaCount - 1))
			remain_area_len = (((fileSize / areaCount) + (fileSize % areaCount)) - (offset[i] + blockSize[i]));
		else
			remain_area_len = ((fileSize / areaCount) - (offset[i] + blockSize[i]));

		//Wrtie remaining plain text
		while (remain_area_len != 0)	{
			if (remain_area_len >= 1024)	{
				//if remained plain text is bigger than plain buffer size(1024).
				result = fread(buf, 1, 1024, in);
				if (result == -1) return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1) return -1;
			}
			else
			{
				//if remained plain text is less than plain buffer size(1024).
				result = fread(buf, 1, remain_area_len, in);
				if (result == -1) return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1) return -1;
			}

			remain_area_len -= result;
		}
	}

	//End file read/write.
	fclose(in);
	fclose(out);

	return total_enc_len;
};

/***********************************************************************************************

		Module Name		:	decFile
		Function		:	Decrypt the encrypted file.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int Decrypt(RSA* PRk, RSA* PUk, char* fileName)
{
	unsigned char cipher_header[256];	//cipher header buffer
	unsigned char plain_header[257];	//plain header buffer
	unsigned char plain_text[256];	//plain text buffer
	unsigned char cipher_text[256];	//cipher text buffer

	char buf[1024];
	char * tok = NULL;
	char extention[1024];
	char decfileName[1024];

	//Variables for generate encrypt area.
	int offset = 0;
	int blockSize = 0;

	int remainLen;
	int remain_area_len = 0;

	int deced_len = 0;
	int plainLen = 0;
	int result;

	int areaCount = 0;
	int fileSize = 0;
	int curareaSize = 0;

	//In/Ouput file pointer
	FILE* out;
	FILE* in;

	in = fopen(fileName, "r+b");

	//Read encrypted header
	result = fread(cipher_header, 1, 256, in); if (result == -1) return -1;
	//And decrypt encrypted header using own's private key.
	result = RSA_private_decrypt(256, cipher_header, plain_header, PRk, RSA_PKCS1_PADDING); if (result == -1) return -1;
	plain_header[256] = 0;


	//Get encrypt information from decrypted header.
	tok = strtok(plain_header, "|");
	areaCount = atoi(tok);

	tok = strtok(NULL, "|");
	strcpy(extention, tok);

	tok = strtok(NULL, "|");
	fileSize = atoi(tok);

	sprintf(decfileName, "dectest.%s", extention);
	out = fopen(decfileName, "w+b");

	//Get encrypt area count
	for (int i = 0; i < areaCount; i++)	{
		//Get offset and block size from header.
		tok = strtok(NULL, "|");
		offset = atoi(tok);

		tok = strtok(NULL, "|");
		blockSize = atoi(tok);
		plainLen = blockSize;

		//Calculate area size.
		if (i == (areaCount - 1))	{
			curareaSize = (fileSize / areaCount) + (fileSize % areaCount) - blockSize + 256;
		}
		else
		{
			curareaSize = (fileSize / areaCount) - blockSize + 256;
		}

		//The remaining length until to be encrypted.
		remainLen = (((fileSize / areaCount) * i) + offset) - ftell(out);

		//Writes the plain text before encrypting area.
		while (remainLen != 0)	{
			if (remainLen >= 1024)	{
				//if remained plain text is bigger than plain buffer size(1024).
				result = fread(buf, 1, 1024, in); if (result == -1) return -1;
				result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
			}
			else
			{
				//if remained plain text is less than plain buffer size(1024).
				result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
				result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
			}

			remainLen = (((fileSize / areaCount) * i) + offset) - ftell(out);
		}

		//Read encrypt area from encrypted file.
		result = fread(cipher_text, 1, 256, in);
		if (result == -1)	return -1;

		//Decrypt encrypted text using sender's public key
		deced_len = RSA_public_decrypt(256, cipher_text, plain_text, PUk, RSA_PKCS1_PADDING);

		//if decrypted text size equal block size, it is right encrypt, decrypt processing.
		if (deced_len == -1 || plainLen != deced_len) return -1;

		//Write decrypted plain text.
		result = fwrite(plain_text, 1, plainLen, out);

		//The remaining length after encrypt area.
		remain_area_len = curareaSize - (offset + 256);

		//Wrtie remaining plain text
		while (remain_area_len != 0)	{
			if (remain_area_len >= 1024)	{
				//if remained plain text is bigger than plain buffer size(1024).
				result = fread(buf, 1, 1024, in);
				if (result == -1)	return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1)	return -1;
			}
			else
			{
				//if remained plain text is less than plain buffer size(1024).
				result = fread(buf, 1, remain_area_len, in);
				if (result == -1)	return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1)	return -1;
			}

			remain_area_len -= result;
		}
	}

	//End file read/write.
	fclose(in);
	fclose(out);
}