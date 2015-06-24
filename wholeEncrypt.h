#pragma warning(disable : 4996)
#ifndef __WHOLE_ENC_H__
#define __WHOLE_ENC_H__

#include <openssl\rand.h>
#include <openssl\rsa.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define max2048Length 245
#define max1024Length 117

int wholeEncFile(RSA* PRk, RSA* PUk, char* fileName);
int wholeDecFile(RSA* PRk, RSA* PUk, char* fileName);

#endif