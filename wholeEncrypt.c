#pragma once
#include "wholeEncrypt.h"

int wholeEncFile(RSA* PRk, RSA* PUk, char* fileName)
{
	FILE * in;
	FILE * out;
	int fileSize, remainLen;
	int enced_len;
	int result;
	unsigned char cipher_text[256];			//암호문 버퍼


	char buf[256];

	//파일 이름을 기준으로 파일 생성.
	in = fopen(fileName, "r+b");
	out = fopen("wholetest.enc", "w+b");

	//끝으로가서 파일 사이즈를 가져온다.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//파일 포인터를 앞으로 이동
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//파일 복사
	/*부분 암호화 전까지는 그냥 복사한다. 이때 현재 내용은 헤더+내용이 된다.*/
	remainLen = fileSize;	//암호화해야할떄까지 남은 길이
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

	//파일 포인터를 앞으로 이동
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//파일 복사
	/*부분 암호화 전까지는 그냥 복사한다. 이때 현재 내용은 헤더+내용이 된다.*/
	remainLen = fileSize;	//암호화해야할떄까지 남은 길이
	while (remainLen > 0)
	{
		result = fread(buf, 1, 256, in); if (result == -1) return -1;
		deced_len = RSA_public_decrypt(result, buf, plain_text, PUk, RSA_PKCS1_PADDING);
		remainLen -= result;
		result = fwrite(plain_text, 1, deced_len, out); if (result == -1) return -1;

	}

	fclose(in);
	fclose(out);
}