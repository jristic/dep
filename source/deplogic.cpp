
namespace deplogic
{

void ComputeFileHash(HANDLE handle, md5::Context* md5Ctx)
{
	uint32_t readSize = 4*1024*1024; // 4 MB
	unsigned char* mem = (unsigned char*)malloc(readSize);
	uint32_t bytesRead = 0;

	uint32_t bytesToRead = fileio::GetFileSize(handle);

	while (bytesRead < bytesToRead)
	{
		u32 bytesToReadThisIteration = min(bytesToRead, readSize);
		fileio::ReadFileAtOffset(handle, mem, bytesRead, bytesToReadThisIteration);
		bytesRead += bytesToReadThisIteration;
		md5::Update(md5Ctx, mem, bytesToReadThisIteration);
	}

	free(mem);
}

md5::Digest ComputeFileHash(HANDLE handle)
{
	md5::Context md5Ctx;
	md5::Init(&md5Ctx);

	ComputeFileHash(handle, &md5Ctx);

	md5::Digest digest;
	md5::Final(&digest, &md5Ctx);

	return digest;
}

md5::Digest ComputeCommandStateHash(
	const char* exePath,
	const char* commandLine,
	const char* currentDirectory)
{
	// Hash the full path to the exe/bat being used, the contents of the exe, 
	//	the command line, and the current working directory.
	md5::Context md5Ctx;
	md5::Init(&md5Ctx);
	md5::Update(&md5Ctx, (unsigned char*)exePath, strlen(exePath));
	md5::Update(&md5Ctx, (unsigned char*)commandLine, strlen(commandLine));
	// The exe file contents
	{
		HANDLE handle = fileio::OpenFileAlways(exePath, GENERIC_READ);
		deplogic::ComputeFileHash(handle, &md5Ctx);
		CloseHandle(handle);
	}
	// The current working directory
	{
		md5::Update(&md5Ctx, (unsigned char*)currentDirectory, strlen(currentDirectory));
	}
	md5::Digest digest;
	md5::Final(&digest, &md5Ctx);

	return digest;
}

void WriteDllPayload(HANDLE process, const char* hash, bool Verbose, bool Force)
{
	uint32_t flags = Verbose << 0 | Force << 1;
	constexpr DWORD payloadSize = sizeof(flags) + 32;
	char payload[payloadSize];
	*((uint32_t*)payload) = flags;
	memcpy(payload + sizeof(flags), hash, 32);
	BOOL success = DetourCopyPayloadToProcess(process, GuidDep, payload, payloadSize);
	Assert(success, "Failed to copy payload, error=%d", GetLastError());
}

bool CheckCacheState(const char* cacheFileName, std::string& outReason)
{
	bool CheckPassed = true; 

	HANDLE depCacheFile = fileio::OpenFileOptional(cacheFileName, GENERIC_READ);
	if (depCacheFile != INVALID_HANDLE_VALUE)
	{
		uint32_t fileSize = fileio::GetFileSize(depCacheFile);
		unsigned char* depCacheContents = (unsigned char*)malloc(fileSize);

		fileio::ReadFile(depCacheFile, depCacheContents, fileSize);
		CloseHandle(depCacheFile);

		unsigned char* fileReadPtr = depCacheContents;
		uint32_t version = cacheformat::ReadUint(fileReadPtr);

		if (version == DepCacheVersion)
		{
			uint32_t fileCount = cacheformat::ReadUint(fileReadPtr);
			for (uint32_t i = 0 ; i < fileCount ; ++i)
			{
				std::string filePath;
				md5::Digest prevHash = cacheformat::ReadFileInfo(fileReadPtr, filePath);
				HANDLE fileHandle = fileio::OpenFileOptional(filePath.c_str(), GENERIC_READ);
				if (fileHandle != INVALID_HANDLE_VALUE)
				{
					md5::Digest currHash = deplogic::ComputeFileHash(fileHandle);
					CloseHandle(fileHandle);
					if (memcmp(currHash.bytes, prevHash.bytes, sizeof(currHash.bytes)) != 0)
					{
						CheckPassed = false;
						outReason = outReason + filePath + 
							" didn't match previous state, rebuild required.";
						break;
					}
				}
				else
				{
					CheckPassed = false;
					outReason = outReason + "Couldn't find dependency " + filePath + 
						", rebuild required.";
					break;
				}
			}
		}
		else
		{
			CheckPassed = false;
			outReason = outReason + "Dep cache file version out of date, rebuild required.";
		}

		free(depCacheContents);
	}
	else
	{
		// No cache file exists, either this command state hasn't been run before
		//	or it returned an error on the last invocation. 
		outReason = outReason + "No cached state for current command state, rebuild required.";
		CheckPassed = false;
	}

	return CheckPassed;
}

} // namespace deplogic
