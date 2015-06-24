#pragma warning(disable : 4996)
#include "partialEncrypt.h"

int encFile1(RSA* PRk, RSA* PUk, char* fileName)
{
	FILE * in;
	FILE * out;
	int fileSize, remainLen;
	int offset, blockSize, enced_len;
	int result;
	unsigned char plain_text[246];			//�� ����
	unsigned char plain_header[246];		//�� ��� ����

	unsigned char cipher_header[256];		//��ȣ�� ��� ����
	unsigned char cipher_text[256];			//��ȣ�� ����


	char buf[1024];
	char * extention;


	int namelen;


	//���� �̸��� �������� ���� ����.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");

	
	extention = strtok(fileName, ".");
	extention = strtok(NULL, ".");
	
	//�����ΰ��� ���� ����� �����´�.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//���ϻ���� �̿��Ͽ� ��ȣȭ�� ���̿�, �κо�ȣȭ�� ���� ������ ���س���.
	blockSize = 122 + (rand() % 122);
	offset = 122 + (rand() % (fileSize - 122));
	offset -= blockSize;


	//��� ����
	sprintf(plain_header, "1|%s|%d|%d|%d", extention, fileSize, offset, blockSize);

	//�޴� ����� ����Ű�� ��� ��ȣȭ(����� ��ȣȭ�� �޴� ������� ����������.)
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);


	//���� �����͸� ������ �̵�
	result = fseek(in, 0, SEEK_SET); if (result == -1) return -1;
	result = fseek(out, 0, SEEK_SET); if (result == -1) return -1;

	//��ȣȭ�� ����� ������Ͽ� �ۼ����ش�.
	result = fwrite(cipher_header, 256, 1, out); if (result == -1) return -1;

	//���� ����
	/*�κ� ��ȣȭ �������� �׳� �����Ѵ�. �̶� ���� ������ ���+������ �ȴ�.*/
	remainLen = offset - ftell(in);	//��ȣȭ�ؾ��ҋ����� ���� ����
	while (remainLen != 0)
	{
		if (remainLen >= 1024)	//����ũ��� 1024�̳�, �������̰� ª������ ���� ���̸�ŭ�� �о��ش�
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


	/*��ȣȭ �ؾ��ϴ� �κ�(offset)��, ��ȣȭ ����(blockSize), ��ȣȭ �� ��� ���Ͽ� �ۼ�.(���� ����� ������ ����������)*/
	result = fread(plain_text, 1, blockSize, in); if (result == -1) return -1;
	enced_len = RSA_private_encrypt(blockSize, plain_text, cipher_text, PRk, RSA_PKCS1_PADDING);
	result = fwrite(cipher_text, 1, enced_len, out); if (result == -1) return -1;

	/*���� �κ� �ۼ�*/
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

	unsigned char plain_text[246];			//�� ����
	unsigned char plain_header[246];		//�� ��� ����

	unsigned char cipher_header[256];		//��ȣ�� ��� ����
	unsigned char cipher_text[256];			//��ȣ�� ����

	unsigned char temp_header[100];		//��� ������ �ӽ÷� ������ ����

	char buf[1024];
	char * extention;

	int namelen;

	/*
	fopen, strtok ����� �� ���� ������ �������� �ʵ��� secure codeing �ϱ�
	*/

	//���� �̸��� �������� ���� ����.
	in = fopen(fileName, "r+b");
	out = fopen("test.enc", "w+b");

	//���� Ȯ���ڸ� ������
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

	//�����ΰ��� ���� ����� �����´�.
	fseek(in, 0, SEEK_END);
	fileSize = ftell(in);

	//����� �� �տ� ��ȣȭ �� �κ��� ������ �Է��ϰ� -> �̷��� ��� �տ� �����൵ �Ǵ� ������ ������ ����� �������� Public Key�� ��ȣȭ�Ǳ� ����
	sprintf(plain_header, "%d|%s|%d", sectionCount, extention, fileSize);

	//��ȣȭ �� �κ��� �� ��ŭ �ݺ��ؼ�
	for (int i = 0; i < sectionCount; i++)	{
		//���ϻ���� �̿��Ͽ� ��ȣȭ�� ���̿�, �κо�ȣȭ�� ���� ������ ���س���.
		
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

		//��� ����
		sprintf(temp_header, "|%d|%d", offset[i], blockSize[i]);
		strcat(plain_header, temp_header);
	}

	//�޴� ����� ����Ű�� ��� ��ȣȭ(����� ��ȣȭ�� �޴� ������� ����������.)
	RSA_public_encrypt(245, plain_header, cipher_header, PUk, RSA_PKCS1_PADDING);

	//���� �����͸� ������ �̵�
	result = fseek(in, 0, SEEK_SET);
	if (result == -1) return -1;

	result = fseek(out, 0, SEEK_SET);
	if (result == -1) return -1;

	//��ȣȭ�� ����� ������Ͽ� �ۼ����ش�.
	result = fwrite(cipher_header, 256, 1, out);
	if (result == -1) return -1;

	for (int i = 0; i < sectionCount; i++)	{
		//���� ����
		/*�κ� ��ȣȭ �������� �׳� �����Ѵ�. �̶� ���� ������ ���+������ �ȴ�.*/
		remainLen = (((fileSize / sectionCount) * i) + offset[i]) - ftell(in);	//��ȣȭ�ؾ��ҋ����� ���� ����
		while (remainLen != 0)
		{
			if (remainLen >= 1024)	//����ũ��� 1024�̳�, �������̰� ª������ ���� ���̸�ŭ�� �о��ش�
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

		/*��ȣȭ �ؾ��ϴ� �κ�(offset)��, ��ȣȭ ����(blockSize), ��ȣȭ �� ��� ���Ͽ� �ۼ�.(���� ����� ������ ����������)*/
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

	//��ȣȭ�� ����� �о� �ڱ� �ڽ��� ����Ű�� �̿��� ��ȣȭ �Ѵ�. (�޴� ������� Ǯ �� �ִ�.)
	result = fread(cipher_header, 1, 256, in); if (result == -1) return -1;
	result = RSA_private_decrypt(256, cipher_header, plain_header, PRk, RSA_PKCS1_PADDING); if (result == -1) return -1;
	plain_header[256] = 0;


	//��ȣȭ�� ����� �̿�, �ʿ� �������� �Ľ�

	tok = strtok(plain_header, "|");
	sectionCount = atoi(tok);

	tok = strtok(NULL, "|");
	strcpy(extention, tok);

	tok = strtok(NULL, "|");
	fileSize = atoi(tok);

	sprintf(decfileName, "dectest.%s", extention);
	out = fopen(decfileName, "w+b");

	//������� ��ȣȭ �� �κ��� ������ŭ ��ȣȭ�� ���� ������ �о�� �Ŀ� ��ȣȭ�� �����Ѵ�.
	for (int i = 0; i < sectionCount; i++)	{
		//������� offset�� blockSize�� ��������
		tok = strtok(NULL, "|");
		offset = atoi(tok);

		tok = strtok(NULL, "|");
		blockSize = atoi(tok);
		plainLen = blockSize;

		//�������� section���� ũ�⸦ �ٽ� ���� �Ŀ�
		if (i == (sectionCount - 1))	{
			cursectionSize = (fileSize / sectionCount) + (fileSize % sectionCount) - blockSize + 256;
		}
		else
		{
			cursectionSize = (fileSize / sectionCount) - blockSize + 256;
		}

		//��ȣȭ�� �κ� �������� ���������� �о ������ ����.
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

		//���Ͽ��� ��ȣȭ�� �κ��� �о�´�.
		result = fread(cipher_text, 1, 256, in);
		if (result == -1)	return -1;

		//��ȣȭ�� �κ��� �۽����� public key�� ��ȣȭ �Ѵ�.(���� ��� ����)
		deced_len = RSA_public_decrypt(256, cipher_text, plain_text, PUk, RSA_PKCS1_PADDING);

		//��ȣȭ�Ǿ� ���� ���̰� ��ȣȭ�� ���̿� ���ٸ� ����� �� ��,��ȣȭ�� ����
		if (deced_len == -1 || plainLen != deced_len) return -1;

		//��ȣȭ�� ���� ���̸�ŭ �ۼ�
		result = fwrite(plain_text, 1, plainLen, out);

		//��ȣȭ�� �޺κ� ���� ���ϱ�
		remain_section_len = cursectionSize - (offset + 256);

		//������ ������ �κ� ����
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