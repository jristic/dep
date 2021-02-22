
namespace fileio {

void MakeDirectory(std::string& directory);

HANDLE CreateFileOverwrite(const char* fileName, u32 desiredAccess);
HANDLE CreateFileTryNew(const char* fileName, u32 desiredAccess);
HANDLE OpenFileAlways(const char* fileName, u32 desiredAccess);
HANDLE OpenFileOptional(const char* fileName, u32 desiredAccess);

void DeleteFile(const char* fileName);

void WriteFile(HANDLE file, const void* payload, u32 payloadSize);

void GetModuleFileName(HMODULE module, char* outFileNameBuffer, DWORD bufferSize);

} // namespace fileio
