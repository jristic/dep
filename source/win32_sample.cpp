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

	FILE* outFile = fopen(argv[2], "w");
	if (outFile==NULL)
	{
		fputs("Output file error\n", stderr);
		exit(2);
	}

	FILE * inFile = fopen ( argv[1] , "r" );
	if (inFile == NULL) 
	{
		fputs("Input file error\n", stderr);
		exit(3);
	}

	fputs("fopen example:\n", outFile);

	int ch;
	while ((ch = fgetc(inFile)) != EOF)
		fputc(ch, outFile);

	fclose(inFile);
	fclose(outFile);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );

	// Start the child processes. 
	{
		if( !CreateProcess( NULL,   // No module name (use command line)
			"built\\copysample64 output.txt output64.txt", // Command line
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

		if (dwResult != 0)
			return dwResult;
	}
	{
		if( !CreateProcess( NULL,   // No module name (use command line)
			"built\\copysample32 output.txt output32.txt", // Command line
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

		if (dwResult != 0)
			return dwResult;
	}


	return 0;
}
