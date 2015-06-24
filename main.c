/*테스트 드라이버 작성*/
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
	//A의 2048 bit RSA키 생성

	RAND_screen();
	keyA = RSA_new();
	keyA = RSA_generate_key(2048, 65535, NULL, NULL);

	//B의 2048 bit RSA키 생성
	RAND_screen();
	keyB = RSA_new();
	keyB = RSA_generate_key(2048, 65535, NULL, NULL);


	//A의 퍼블릭키 생성
	pkA = (unsigned char *)malloc(2048);
	memset(pkA, 0, 2048);
	temp_pkA = pkA;
	pkA_len = i2d_RSAPublicKey(keyA, &pkA);
	pkA = temp_pkA;


	//B의 퍼블릭키 생성
	pkB = (unsigned char *)malloc(2048);
	memset(pkB, 0, 2048);
	temp_pkB = pkB;
	pkB_len = i2d_RSAPublicKey(keyB, &pkB); //v퍼블릭키 추출
	pkB = temp_pkB;

	//각자의 퍼블릭 키를 등록한다.
	pkeyB = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkB, (long)pkB_len);
	pkeyA = d2i_RSAPublicKey(NULL, (const unsigned char**)&pkA, (long)pkA_len);


	/*
	//암호화 한 파일 생성 및 시간 출력
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

			//복호화 한 파일 생성 및 시간 출력
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

			//복호화 한 파일 생성 및 시간 출력
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