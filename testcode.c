/***********************************************************************************************

		testcode.c

		Discription		:	Test Case for performance evaluation of partial encryption.
		Purpose			:	Compare partial encryption algorithm and whole encryption algorithm.
		Requirements	:	Openssl library to be installed.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
#pragma once
#pragma warning(disable : 4996)

#include <openssl\rand.h>
#include <openssl\rsa.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "partialEncrypt.h"
#include "wholeEncrypt.h"

#define max2048Length 245
#define max1024Length 117

/***********************************************************************************************

		Module Name		:	printMenu
		Function		:	Print menu for running testcase.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
void printMenu()
{
	printf("\n*****PartialEncryptionTestModule******\n");
	printf("1. Partial Encryption, Decryption Test\n");
	printf("2. Whole Encryption, Decryption Test\n");
	printf("3. Exit\n");
	printf("**************************************\n\n");
	return;
}

/***********************************************************************************************

		Module Name		:	main
		Function		:	Compare partial encryption algorithm and whole encrypt algorithm.
		Author			:	Kyewan Ahn, Junki Kim, Youngwoo Jeon
		Revision		:	2015/06/25
		Modified		:	2015/06/25	Junki Kim

***********************************************************************************************/
int main(int argc, char* argv[])
{
	//variables for calc RSA running time
	clock_t start_time, end_time;

	//RSA Key
	RSA *keyA, *keyB, *pkeyA, *pkeyB;

	char buf[256];
	int pkA_len, pkB_len;
	int CMD;
	unsigned char *pkA, *temp_pkA;
	unsigned char *pkB, *temp_pkB;

	//target file name
	char testFileName1[] = "test1.png";
	char testFileName2[] = "test2.png";

	time_t ltime;

	double dEtime;
	double dDtime;
	struct tm *today;

	FILE * partialLog;
	FILE * wholeLog;

	int blSize;
	long esec, dsec;

	//open logfile.
	partialLog = fopen("partialLog.log", "a+t");
	wholeLog = fopen("wholeLog.log", "a+t");

	//Get Start time.
	srand(time(NULL));
	time(&ltime);
	today = localtime(&ltime);
	printf("Starting Time: %s", asctime(today));

	//Generate A's 2048 bits RSA Key.
	RAND_screen();
	keyA = RSA_new();
	keyA = RSA_generate_key(2048, 65535, NULL, NULL);

	//Generate B's 2048 bits RSA Key.
	RAND_screen();
	keyB = RSA_new();
	keyB = RSA_generate_key(2048, 65535, NULL, NULL);


	//Generate A's Public Key.
	pkA = (unsigned char *)malloc(2048);
	memset(pkA, 0, 2048);
	temp_pkA = pkA;
	pkA_len = i2d_RSAPublicKey(keyA, &pkA);
	pkA = temp_pkA;


	//Generate B's Public Key.
	pkB = (unsigned char *)malloc(2048);
	memset(pkB, 0, 2048);
	temp_pkB = pkB;
	pkB_len = i2d_RSAPublicKey(keyB, &pkB);
	pkB = temp_pkB;

	//Registe each Public Key.
	pkeyB = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkB, (long)pkB_len);
	pkeyA = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkA, (long)pkA_len);

	while (1)
	{
		//Print program menu.
		printMenu();
		printf("CMD> ");
		scanf("%d", &CMD);
		switch (CMD)
		{
		case 1:
			/*
				Partial Encryption / Decryption
			*/
			printf("1. Partial Encryption, Decryption Test\n");

			time(&ltime);
			today = localtime(&ltime);
			printf("Starting Time: %s", asctime(today));

			start_time = clock();                  // Start_Time

			//Encrypt 10 areas of the file.
			blSize = encFileTen(keyA, pkeyB, testFileName1, 10);

			end_time = clock();                   // End_Time
			dEtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
			printf("Encrypt time: %fsec\n", dEtime);

			//Create decrypted file and ptrint time that create decrypt file.
			start_time = clock();                  // Start_Time
			
			//Decrypt the encrypted file.
			decFile(keyB, pkeyA, "test.enc");
			end_time = clock();                   // End_Time

			dDtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
			printf("Decrypt time: %fsec\n", dDtime);

			sprintf(buf, "%d\n%f\n%f\n\n", blSize, dEtime, dDtime);
			fwrite(buf, strlen(buf), 1, partialLog);
			break;
		case 2:
			/*
				Whole Encryption / Decryption
			*/
			printf("2. Whole Encryption, Decryption Test\n");
			time(&ltime);
			today = localtime(&ltime);
			printf("Starting Time: %s", asctime(today));

			start_time = clock();                  // Start_Time

			//Encrypt the whole of the file.
			blSize = wholeEncFile(keyA, pkeyB, testFileName2);

			end_time = clock();                   // End_Time
			dEtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

			printf("Encrypt time: %fsec\n", dEtime);
			start_time = clock();                  // Start_Time

			//Decrypt the encrypted file.
			wholeDecFile(keyB, pkeyA, "wholeDectest.dec");
			end_time = clock();                   // End_Time

			dDtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
			//Create decrypted file and ptrint time that create decrypt file.
			printf("Decrypt time: %fsec\n", dDtime);

			sprintf(buf, "%d\n%f\n%f\n\n", blSize, dEtime, dDtime);
			fwrite(buf, strlen(buf), 1, wholeLog);
			break;
		case 3:
			/*
				Terminate program
			*/
			printf("Thank you!!\n\n\n");
			fclose(partialLog);
			fclose(wholeLog);
			return 0;
		default:
			/*
				When enter the other command.
			*/
			printf("Wrong Command!!\n");
			printMenu();
			break;
		}
	}
}