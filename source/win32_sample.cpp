#include <stdio.h>
#include <stdlib.h>

int main ()
{
	FILE * pFile = fopen ( "input.txt" , "r" );
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
		exit (3);
	}

	/* the whole file is now loaded in the memory buffer. */
	// terminate
	fclose(pFile);

	pFile = fopen("output.txt", "w");
	if (pFile!=NULL)
	{
		fputs("fopen example:\n", pFile);
		fwrite(buffer, 1, lSize, pFile);
		fclose(pFile);
	}

	free(buffer);
	return 0;
}
