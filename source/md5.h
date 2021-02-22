// ***************************************************************
// This work is derived from the RSA Data Security, Inc. MD5 
//  Message-Digest Algorithm
// ***************************************************************

namespace md5 {

struct Context {
	uint32_t state[4];                                /* state (ABCD) */
	uint32_t count[2];     /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
};
struct Digest {
	unsigned char bytes[16];
};

Digest ComputeDigest(unsigned char* data, size_t length);
std::string DigestToString(Digest* digest);
void Init(Context *);
void Update(Context *, unsigned char *, size_t);
void Final(Digest*, Context *);

} // namespace md5
