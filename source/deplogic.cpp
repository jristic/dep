
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

} // namespace deplogic
