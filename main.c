/*�׽�Ʈ ����̹� �ۼ�*/
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

#define TEST 1
char testFileName[] = "test.png";

void printMenu();

int main(int argc, char* argv[])
{
	clock_t start_time, end_time;      // clock_t 

	RSA *keyA, *keyB, *pkeyA, *pkeyB;
	char buf[256];
	int pkA_len, pkB_len;
	int CMD;
	unsigned char *pkA, *temp_pkA;
	unsigned char *pkB, *temp_pkB;

	time_t ltime;

	double dEtime;
	double dDtime;
	struct tm *today;

	FILE * partialLog;
	FILE * wholeLog;

	int blSize;
	long esec, dsec;


	partialLog = fopen("partialLog.log", "a+t");
	wholeLog = fopen("wholeLog.log", "a+t");


	/*
	#if TEST==0
	if (argc != 2)
	{
	printf("Usage: %s filename\n", argv[0]);
	return -1;
	}
	#endif

	*/

	srand(time(NULL));


	time(&ltime);
	today = localtime(&ltime);
	printf("Starting Time: %s", asctime(today));
	//A�� 2048 bit RSAŰ ����

	RAND_screen();
	keyA = RSA_new();
	keyA = RSA_generate_key(2048, 65535, NULL, NULL);

	//B�� 2048 bit RSAŰ ����
	RAND_screen();
	keyB = RSA_new();
	keyB = RSA_generate_key(2048, 65535, NULL, NULL);


	//A�� �ۺ�Ű ����
	pkA = (unsigned char *)malloc(2048);
	memset(pkA, 0, 2048);
	temp_pkA = pkA;
	pkA_len = i2d_RSAPublicKey(keyA, &pkA);
	pkA = temp_pkA;


	//B�� �ۺ�Ű ����
	pkB = (unsigned char *)malloc(2048);
	memset(pkB, 0, 2048);
	temp_pkB = pkB;
	pkB_len = i2d_RSAPublicKey(keyB, &pkB); //v�ۺ�Ű ����
	pkB = temp_pkB;

	//������ �ۺ� Ű�� ����Ѵ�.
	pkeyB = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkB, (long)pkB_len);
	pkeyA = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkA, (long)pkA_len);


	/*
	//��ȣȭ �� ���� ���� �� �ð� ���
	#if TEST==0
	encFile(keyA, pkeyB, argv[1]);
	#else
	encFile(keyA, pkeyB, "test.png");
	#endif*/


	while (1)
	{
		printMenu();
		printf("CMD> ");
		scanf("%d", &CMD);
		switch (CMD)
		{
		case 1:

			printf("1. Partial Encryption, Decryption Test\n");

			time(&ltime);
			today = localtime(&ltime);
			printf("Starting Time: %s", asctime(today));

			start_time = clock();                  // Start_Time
			//blSize = encFile1(keyA, pkeyB, testFileName);
			blSize = encFile2(keyA, pkeyB, testFileName, 10);
			end_time = clock();                   // End_Time

			dEtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

			printf("Encrypt time: %fsec\n", dEtime);

			//��ȣȭ �� ���� ���� �� �ð� ���
			start_time = clock();                  // Start_Time
			decFile(keyB, pkeyA, "test.enc");
			end_time = clock();                   // End_Time

			dDtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
			printf("Decrypt time: %fsec\n", dDtime);

			sprintf(buf, "%d\n%f\n%f\n\n", blSize, dEtime, dDtime);
			fwrite(buf, strlen(buf), 1, partialLog);
			break;
		case 2:
			printf("2. Whole Encryption, Decryption Test\n");
			time(&ltime);
			today = localtime(&ltime);
			printf("Starting Time: %s", asctime(today));

			start_time = clock();                  // Start_Time
			blSize = wholeEncFile(keyA, pkeyB, testFileName);
			end_time = clock();                   // End_Time

			dEtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

			printf("Encrypt time: %fsec\n", dEtime);



			start_time = clock();                  // Start_Time
			wholeDecFile(keyB, pkeyA, "wholeDectest.dec");
			end_time = clock();                   // End_Time

			dDtime = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

			//��ȣȭ �� ���� ���� �� �ð� ���
			printf("Decrypt time: %fsec\n", dDtime);


			sprintf(buf, "%d\n%f\n%f\n\n", blSize, dEtime, dDtime);
			fwrite(buf, strlen(buf), 1, wholeLog);
			break;
		case 3:
			printf("Thank you!!\n\n\n");
			fclose(partialLog);
			fclose(wholeLog);
			return 0;
		default:
			printf("Wrong Command!!\n");
			printMenu();
			break;
		}
	}



}


void printMenu()
{
	printf("\n*****PartialEncryptionTestModule******\n");
	printf("1. Partial Encryption, Decryption Test\n");
	printf("2. Whole Encryption, Decryption Test\n");
	printf("3. Exit\n");
	printf("**************************************\n\n");
	return;
}