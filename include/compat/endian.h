/* Compatibility header for converting BSD/Linux macros to their Darwin equivalents. */

#ifndef _COMPAT_ENDIAN_H
#define _COMPAT_ENDIAN_H

#include <libkern/OSByteOrder.h>

#if defined(__LITTLE_ENDIAN__)
#	define __LITTLE_ENDIAN 1234
#	define __LITTLE_ENDIAN_BITFIELD
#elif defined(__BIG_ENDIAN__)
#	define __BIG_ENDIAN 4321
#	define __BIG_ENDIAN_BITFIELD
#endif

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define betoh16(x) OSSwapBigToHostInt16(x)
#define betoh32(x) OSSwapBigToHostInt32(x)
#define betoh64(x) OSSwapBigToHostInt64(x)

#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define letoh16(x) OSSwapLittleToHostInt16(x)
#define letoh32(x) OSSwapLittleToHostInt32(x)
#define letoh64(x) OSSwapLittleToHostInt64(x)

#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#endif	/* _COMPAT_ENDIAN_H_ */
