/***********************************************************************************************

		wholeEncrypt.h

		Discription		:	Encrypt / Decrypt the whole of the file using RSA algorithm.
		Purpose			:	Using a control group.
		Requirements	:	Openssl library to be installed.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/

#pragma warning(disable : 4996)
#pragma once

#ifndef __WHOLE_ENC_H__
#define __WHOLE_ENC_H__

#include <openssl\rand.h>
#include <openssl\rsa.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define max2048Length 245
#define max1024Length 117

/***********************************************************************************************

		Module Name		:	wholeEncFile
		Function		:	Encrypt the whole of the file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int wholeEncFile(RSA* PRk, RSA* PUk, char* fileName);

/***********************************************************************************************

		Module Name		:	wholeEncFile
		Function		:	Decrypt the encrypted file.
		Author			:	Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int wholeDecFile(RSA* PRk, RSA* PUk, char* fileName);

#endif