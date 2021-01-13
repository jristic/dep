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
	FILE * pFile = fopen ( argv[1] , "r" );
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

	pFile = fopen(argv[2], "w");
	if (pFile!=NULL)
	{
		fputs("fopen example:\n", pFile);
		fwrite(buffer, 1, lSize, pFile);
		fclose(pFile);
	}
	free(buffer);

	STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	 // Start the child process. 
    if( !CreateProcess( NULL,   // No module name (use command line)
        "robocopy output.txt output2.txt",        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf( "CreateProcess failed (%d).\n", GetLastError() );
        exit(4);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD dwResult = 0;
	if (!GetExitCodeProcess(pi.hProcess, &dwResult)) {
		printf("dep.exe: GetExitCodeProcess failed: %d\n", GetLastError());
		exit(5);
	}

	return dwResult;
}
