/*******************************************************************************
  Copyright (c) 2011-2014 Dmitry Matveev <me@dmitrymatveev.co.uk>
  Copyright (c) 2014-2018 Vladimir Kondratyev <vladimir@kondratyev.su>
  SPDX-License-Identifier: MIT

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*******************************************************************************/

#ifndef __COMPAT_H__
#define __COMPAT_H__

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __APPLE__
#include "tree.h"
#include "pthread_barrier.h"
#else
#include <sys/tree.h>
#endif

/*
 * Minimal pthread condition variable-based POSIX semaphore shim.
 * Used as neither Darwin nor valgrind supports POSIX semafores.
 */
typedef struct {
    int val;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} ik_sem_t;
#define ik_sem_init(sem, pshared, value) ({ \
    pthread_mutex_init(&(sem)->mutex, NULL); \
    pthread_cond_init(&(sem)->cond, NULL); \
    (sem)->val = value; \
    0; \
})
#define ik_sem_wait(sem) ({ \
    pthread_mutex_lock(&(sem)->mutex); \
    while ((sem)->val == 0) { \
        pthread_cond_wait(&(sem)->cond, &(sem)->mutex); \
    } \
    --(sem)->val; \
    pthread_mutex_unlock(&(sem)->mutex); \
    0; \
})
#define ik_sem_post(sem) ({ \
    pthread_mutex_lock(&(sem)->mutex); \
    ++(sem)->val; \
    pthread_cond_broadcast(&(sem)->cond); \
    pthread_mutex_unlock(&(sem)->mutex); \
    0; \
})
#define ik_sem_destroy(sem) ({ \
    pthread_cond_destroy(&(sem)->cond); \
    pthread_mutex_destroy(&(sem)->mutex); \
})

#ifndef DTTOIF
#define DTTOIF(dirtype) ((dirtype) << 12)
#endif

#ifndef SIZE_MAX
#define SIZE_MAX SIZE_T_MAX
#endif

#ifndef nitems
#define nitems(x) (sizeof((x)) / sizeof((x)[0]))
#endif

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__)
#define IOV_MAX 1024
#endif
#endif

#ifndef AT_FDCWD
#define AT_FDCWD		-100
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW	0x200 /* Do not follow symbolic links */
#endif

#endif /* __COMPAT_H__ */
