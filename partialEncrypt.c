#pragma warning(disable : 4996)
#include "partialEncrypt.h"

int encFile1(RSA* PRk, RSA* PUk, char* fileName)
{
	FILE * in;
	FILE * out;
	int fileSize, remainLen;
	int offset, blockSize, enced_len;
	int result;
	unsigned char plain_text[246];			//평문 버퍼
	unsigned char plain_header[246];		//평문 헤더 버퍼

	unsigned char cipher_header[256];		//암호문 헤더 버퍼
	unsigned char cipher_text[256];			//암호문 버퍼


	char buf[1024];
	char * extention;


	int namelen;


	//파일 이름을 기준으로 파일 생성.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");

	
	extention = strtok(fileName, ".");
	extention = strtok(NULL, ".");
	
	//끝으로가서 파일 사이즈를 가져온다.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//파일사이즈를 이용하여 암호화할 길이와, 부분암호화의 시작 지점을 구해낸다.
	blockSize = 122 + (rand() % 122);
	offset = 122 + (rand() % (fileSize - 122));
	offset -= blockSize;


	//헤더 생성
	sprintf(plain_header, "1|%s|%d|%d|%d", extention, fileSize, offset, blockSize);

	//받는 사람의 공개키로 헤더 암호화(헤더의 복호화는 받는 사람만이 가능해진다.)
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);


	//파일 포인터를 앞으로 이동
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//암호화된 헤더를 출력파일에 작성해준다.
	result = fwrite(cipher_header, 256, 1, out); if (result == -1) return -1;

	//파일 복사
	/*부분 암호화 전까지는 그냥 복사한다. 이때 현재 내용은 헤더+내용이 된다.*/
	remainLen = offset - ftell(in);	//암호화해야할떄까지 남은 길이
	while (remainLen != 0)
	{
		if (remainLen >= 1024)	//버퍼크기는 1024이나, 남은길이가 짧을때는 남은 길이만큼만 읽어준다
		{
			result = fread(buf, 1, 1024, in); if (result == -1) return -1;
			result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
		}
		else
		{
			result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
			result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
		}
		remainLen = offset - ftell(in);

	}


	/*암호화 해야하는 부분(offset)을, 암호화 길이(blockSize), 암호화 후 출력 파일에 작성.(보낸 사람의 인증이 가능해진다)*/
	result = fread(plain_text, 1, blockSize, in); if (result == -1) return -1;
	enced_len = RSA_private_encrypt(blockSize, plain_text, cipher_text, PRk, RSA_PKCS1_PADDING);
	result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;

	/*남은 부분 작성*/
	while (!feof(in))
	{
		result = fread(buf, 1, 1024, in); if (result == -1) return -1;
		result = fwrite(buf, 1, result, out); if (result == -1) return -1;
	}

	fclose(in);
	fclose(out);

	return blockSize;
};

int encFile2(RSA* PRk, RSA* PUk, char* fileName, int sectionCount)
{
	FILE * in;
	FILE * out;
	int fileSize, remainLen;

	int offset[10] = { 0 };
	int blockSize[10] = { 0 };
	int enced_len;
	int result;

	int total_enc_len = 0;
	int remain_section_len = 0;

	unsigned char plain_text[246];			//평문 버퍼
	unsigned char plain_header[246];		//평문 헤더 버퍼

	unsigned char cipher_header[256];		//암호문 헤더 버퍼
	unsigned char cipher_text[256];			//암호문 버퍼

	unsigned char temp_header[100];		//헤더 정보를 임시로 저장할 버퍼

	char buf[1024];
	char * extention;

	int namelen;

	/*
	fopen, strtok 사용할 때 버퍼 사이즈 오버하지 않도록 secure codeing 하기
	*/

	//파일 이름을 기준으로 파일 생성.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");

	//파일 확장자를 가져옴
	extention = strtok(fileName, ".");
	extention = strtok(NULL, ".");

	/*
	namelen = strlen(fileName);
	while (1)
	{
		if (fileName[namelen] == '.')
			break;
		namelen--;
	}
	
	extention = _strdup(&fileName[namelen + 1]);
	*/

	//끝으로가서 파일 사이즈를 가져온다.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//헤더의 맨 앞에 암호화 된 부분의 갯수를 입력하고 -> 이렇게 헤더 앞에 적어줘도 되는 이유는 어차피 헤더는 수신자의 Public Key로 암호화되기 때문
	sprintf(plain_header, "%d|%s|%d", sectionCount, extention, fileSize);

	//암호화 할 부분의 수 만큼 반복해서
	for (int i = 0; i < sectionCount; i++)	{
		//파일사이즈를 이용하여 암호화할 길이와, 부분암호화의 시작 지점을 구해낸다.
		
		if (i == (sectionCount - 1))	{
			blockSize[i] = (rand() % ((fileSize / sectionCount) + (fileSize % sectionCount)));

			if (blockSize[i] > 245)	blockSize[i] = (blockSize[i] % 245);

			offset[i] = (rand() % (((fileSize / sectionCount) + (fileSize % sectionCount)) - blockSize[i]));
		}
		else
		{
			blockSize[i] = (rand() % (fileSize / sectionCount));

			if (blockSize[i] > 245)	blockSize[i] = (blockSize[i] % 245);

			offset[i] = (rand() % ((fileSize / sectionCount) - blockSize[i]));
		}

		//헤더 생성
		sprintf(temp_header, "|%d|%d", offset[i], blockSize[i]);
		strcat(plain_header, temp_header);
	}

	//받는 사람의 공개키로 헤더 암호화(헤더의 복호화는 받는 사람만이 가능해진다.)
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);

	//파일 포인터를 앞으로 이동
	result = fseek(in, 0, SEEK_SET);
	if (result == -1) return -1;

	result = fseek(out, 0, SEEK_SET);
	if (result == -1) return -1;

	//암호화된 헤더를 출력파일에 작성해준다.
	result = fwrite(cipher_header, 256, 1, out);
	if (result == -1) return -1;

	for (int i = 0; i < sectionCount; i++)	{
		//파일 복사
		/*부분 암호화 전까지는 그냥 복사한다. 이때 현재 내용은 헤더+내용이 된다.*/
		remainLen = (((fileSize / sectionCount) * i) + offset[i]) - ftell(in);	//암호화해야할떄까지 남은 길이
		while (remainLen != 0)
		{
			if (remainLen >= 1024)	//버퍼크기는 1024이나, 남은길이가 짧을때는 남은 길이만큼만 읽어준다
			{
				result = fread(buf, 1, 1024, in); if (result == -1) return -1;
				result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
			}
			else
			{
				result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
				result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
			}

			remainLen = (((fileSize / sectionCount) * i) + offset[i]) - ftell(in);
		}

		/*암호화 해야하는 부분(offset)을, 암호화 길이(blockSize), 암호화 후 출력 파일에 작성.(보낸 사람의 인증이 가능해진다)*/
		result = fread(plain_text, 1, blockSize[i], in); if (result == -1) return -1;
		enced_len = RSA_private_encrypt(blockSize[i], plain_text, cipher_text, PRk, RSA_PKCS1_PADDING);
		result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;

		total_enc_len += enced_len;
		if (i == (sectionCount - 1))
			remain_section_len = (((fileSize / sectionCount) + (fileSize % sectionCount)) - (offset[i] + blockSize[i]));
		else
			remain_section_len = ((fileSize / sectionCount) - (offset[i] + blockSize[i]));

		while (remain_section_len != 0)	{
			if (remain_section_len >= 1024)	{
				result = fread(buf, 1, 1024, in);
				if (result == -1) return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1) return -1;
			}
			else
			{
				result = fread(buf, 1, remain_section_len, in);
				if (result == -1) return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1) return -1;
			}

			remain_section_len -= result;
		}
	}

	fclose(in);
	fclose(out);

	return total_enc_len;
};

int decFile(RSA* PRk, RSA* PUk, char* fileName)
{
	unsigned char cipher_header[256];	//
	unsigned char plain_header[257];
	unsigned char plain_text[256];
	unsigned char cipher_text[256];

	char buf[1024];
	char * tok = NULL;
	char extention[1024];
	char decfileName[1024];
	int offset = 0;
	int blockSize = 0;
	int remainLen;
	int remain_section_len = 0;

	int deced_len = 0;
	int plainLen = 0;
	int result;

	int sectionCount = 0;
	int fileSize = 0;
	int cursectionSize = 0;

	FILE* out;
	FILE* in;

	in = fopen(fileName, "r+b");

	//암호화된 헤더를 읽어 자기 자신의 개인키를 이용해 복호화 한다. (받는 사람만이 풀 수 있다.)
	result = fread(cipher_header, 1, 256, in); if (result == -1) return -1;
	result = RSA_private_decrypt(256, cipher_header, plain_header, PRk, RSA_PKCS1_PADDING); if (result == -1) return -1;
	plain_header[256] = 0;


	//복호화된 헤더를 이용, 필요 정보들을 파싱

	tok = strtok(plain_header, "|");
	sectionCount = atoi(tok);

	tok = strtok(NULL, "|");
	strcpy(extention, tok);

	tok = strtok(NULL, "|");
	fileSize = atoi(tok);

	sprintf(decfileName, "dectest.%s", extention);
	out = fopen(decfileName, "w+b");

	//헤더에서 암호화 한 부분의 갯수만큼 암호화에 대한 정보를 읽어온 후에 복호화를 진행한다.
	for (int i = 0; i < sectionCount; i++)	{
		//헤더에서 offset과 blockSize를 가져오고
		tok = strtok(NULL, "|");
		offset = atoi(tok);

		tok = strtok(NULL, "|");
		blockSize = atoi(tok);
		plainLen = blockSize;

		//나뉘어진 section별로 크기를 다시 구한 후에
		if (i == (sectionCount - 1))	{
			cursectionSize = (fileSize / sectionCount) + (fileSize % sectionCount) - blockSize + 256;
		}
		else
		{
			cursectionSize = (fileSize / sectionCount) - blockSize + 256;
		}

		//암호화된 부분 전까지는 정상적으로 읽어서 파일을 쓴다.
		remainLen = (((fileSize / sectionCount) * i) + offset) - ftell(out);
		while (remainLen != 0)	{
			if (remainLen >= 1024)	{
				result = fread(buf, 1, 1024, in); if (result == -1) return -1;
				result = fwrite(buf, 1, 1024, out); if (result == -1) return -1;
			}
			else
			{
				result = fread(buf, 1, remainLen, in); if (result == -1) return -1;
				result = fwrite(buf, 1, remainLen, out); if (result == -1) return -1;
			}

			remainLen = (((fileSize / sectionCount) * i) + offset) - ftell(out);
		}

		//파일에서 암호화된 부분을 읽어온다.
		result = fread(cipher_text, 1, 256, in);
		if (result == -1)	return -1;

		//암호화된 부분을 송신자의 public key로 복호화 한다.(보낸 사람 인증)
		deced_len = RSA_public_decrypt(256, cipher_text, plain_text, PUk, RSA_PKCS1_PADDING);

		//복호화되어 나온 길이가 암호화된 길이와 같다면 제대로 된 암,복호화의 인증
		if (deced_len == -1 || plainLen != deced_len) return -1;

		//복호화된 평문을 길이만큼 작성
		result = fwrite(plain_text, 1, plainLen, out);

		//암호화된 뒷부분 길이 구하기
		remain_section_len = cursectionSize - (offset + 256);

		//파일의 나머지 부분 쓰기
		while (remain_section_len != 0)	{
			if (remain_section_len >= 1024)	{
				result = fread(buf, 1, 1024, in);
				if (result == -1)	return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1)	return -1;
			}
			else
			{
				result = fread(buf, 1, remain_section_len, in);
				if (result == -1)	return -1;

				result = fwrite(buf, 1, result, out);
				if (result == -1)	return -1;
			}

			remain_section_len -= result;
		}
	}

	fclose(in);
	fclose(out);
}