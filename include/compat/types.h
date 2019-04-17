#ifdef __APPLE__

#ifndef _COMPAT_TYPES_H
#define _COMPAT_TYPES_H

#include <mach/mach_types.h>
#include <sys/types.h>

typedef u_int8_t        __u8;
typedef u_int16_t       __u16;
typedef u_int32_t       __u32;
typedef u_int64_t       __u64;
typedef int8_t          __s8;
typedef int16_t         __s16;
typedef int32_t         __s32;
typedef int64_t         __s64;

#endif /* _COMPAT_TYPES_H */

#endif /* __APPLE__ */
