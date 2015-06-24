#pragma warning(disable : 4996)
#ifndef __PART_ENC_H__
#define __PART_ENC_H__

#include <openssl\rand.h>
#include <openssl\rsa.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define max2048Length 245
#define max1024Length 117

int encFile1(RSA* PRk, RSA* PUk, char* fileName);
int encFile2(RSA* PRk, RSA* PUk, char* fileName, int sectionCount);
int decFile(RSA* PRk, RSA* PUk, char* fileName);

#endif