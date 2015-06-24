/***********************************************************************************************

		partialEncrypt.h

		Discription		:	Encrypt / Decrypt the specific area of the file using RSA algorithm.
		Purpose			:	1) Providing a high level of security.
							2) Improvement speed of the conventional RSA algorithm.
		Requirements	:	Openssl library to be installed.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
#pragma warning(disable : 4996)
#pragma once

#ifndef __PART_ENC_H__
#define __PART_ENC_H__

#include <openssl\rand.h>
#include <openssl\rsa.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define max2048Length 245
#define max1024Length 117

/***********************************************************************************************

		Module Name		:	encFileOne
		Function		:	Encrypt an area of the file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int encFileOne(RSA* PRk, RSA* PUk, char* fileName);

/***********************************************************************************************

		Module Name		:	encFileTen
		Function		:	Encrypt some area of the file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

*******************************************************************/
int encFileTen(RSA* PRk, RSA* PUk, char* fileName, int sectionCount);

/***********************************************************************************************

		Module Name		:	decFile
		Function		:	Decrypt the encrypted file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int decFile(RSA* PRk, RSA* PUk, char* fileName);

#endif