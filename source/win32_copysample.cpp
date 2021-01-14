#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		fputs("Invalid number of args\n", stderr);
		exit(1);
	}
	FILE * pFile = fopen ( argv[1] , "rb" );
	if (pFile == NULL) 
	{
		fputs("File error\n", stderr);
		exit(1);
	}

	// obtain file size:
	fseek(pFile , 0 , SEEK_END);
	long int lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	char* buffer = (char*) malloc(sizeof(char)*lSize);
	if (buffer == nullptr)
	{
		fputs("Memory error\n",stderr);
		exit(2);
	}

	// copy the file into the buffer:
	size_t result = fread(buffer,1,lSize,pFile);
	if (result != size_t(lSize))
	{
		fputs("Reading error\n",stderr);
		printf("expected: %d, read: %zu", lSize, result);
		exit (3);
	}

	fclose(pFile);

	pFile = fopen(argv[2], "wb");
	if (pFile!=NULL)
	{
		fwrite(buffer, 1, lSize, pFile);
		fclose(pFile);
	}
	free(buffer);

	return 0;
}
