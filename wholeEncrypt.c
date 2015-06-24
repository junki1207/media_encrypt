/***********************************************************************************************

		wholeEncrypt.c

		Discription		:	Encrypt / Decrypt the whole of the file using RSA algorithm.
		Purpose			:	Using a control group.
		Requirements	:	Openssl library to be installed.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/

#pragma once
#pragma warning(disable : 4996)

#include "wholeEncrypt.h"

/***********************************************************************************************

		Module Name		:	wholeEncFile
		Function		:	Encrypt the whole of the file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int wholeEncFile(RSA* PRk, RSA* PUk, char* fileName)
{
	FILE * in;
	FILE * out;
	int fileSize, remainLen;
	int enced_len;
	int result;
	unsigned char cipher_text[256];


	char buf[256];

	//Open target file and create encryted file.
	in = fopen(fileName, "r+b");
	out = fopen("wholetest.enc", "w+b");

	//Get target file's file size.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//Move the file pointer to the front.
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//the remaining length until to be encrypted.
	remainLen = fileSize;

	//Writes the plain text before encrypting area.
	while (!feof(in))
	{
		result = fread(buf, 1, 245, in); if (result == -1) return -1;
		enced_len = RSA_private_encrypt(result, buf, cipher_text, PRk, RSA_PKCS1_PADDING);
		result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;
	}

	fclose(in);
	fclose(out);

	return fileSize;

}

/***********************************************************************************************

		Module Name		:	wholeEncFile
		Function		:	Decrypt the encrypted file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int wholeDecFile(RSA* PRk, RSA* PUk, char* fileName)
{

	char buf[256];
	char plain_text[256];
	int deced_len;
	int remainLen;
	int fileSize;
	int result;
	FILE* out;
	FILE* in;

	in = fopen("wholetest.enc", "r+b");
	out = fopen(fileName, "w+b");

	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//Move the file pointer to the front.
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//the remaining length until to be encrypted.
	remainLen = fileSize;

	//Writes the plain text before encrypting area.
	while (remainLen > 0)
	{
		result = fread(buf, 1, 256, in); if (result == -1) return -1;
		//Decrypt the encrypted area.
		deced_len = RSA_public_decrypt(result, buf, plain_text, PUk, RSA_PKCS1_PADDING);
		remainLen -= result;
		result = fwrite(plain_text, 1, deced_len, out); if (result == -1) return -1;
	}

	fclose(in);
	fclose(out);
}