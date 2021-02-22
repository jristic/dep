
namespace cacheformat
{

void WriteUint(HANDLE file, uint32_t count)
{
	fileio::WriteFile(file, &count, sizeof(count));
}

void WriteFileInfo(HANDLE file, const char* path, md5::Digest& hash)
{
	uint32_t pathLength = (uint32_t)strlen(path);

	fileio::WriteFile(file, &pathLength, sizeof(pathLength));
	fileio::WriteFile(file, path, pathLength);
	fileio::WriteFile(file, hash.bytes, sizeof(hash.bytes));
}

uint32_t ReadUint(unsigned char*& fileData)
{
	uint32_t count = *((uint32_t*)fileData);
	fileData += sizeof(count);
	return count;
}

md5::Digest ReadFileInfo(unsigned char*& fileData, std::string& outPath)
{
	uint32_t pathLength = ReadUint(fileData);

	outPath = std::string((char*)fileData, pathLength);
	fileData += pathLength;

	md5::Digest digest;
	memcpy(digest.bytes, fileData, sizeof(digest.bytes));
	fileData += sizeof(digest.bytes);

	return digest;
}

} // namespace cacheformat