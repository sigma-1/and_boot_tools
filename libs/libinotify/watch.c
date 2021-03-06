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

#include <compat.h>

#include <errno.h>  /* errno */
#include <fcntl.h>  /* open */
#include <unistd.h> /* close */
#include <string.h> /* strdup */
#include <stdlib.h> /* free */
#include <assert.h>

#include <sys/types.h>
#include <sys/event.h> /* kevent */
#include <sys/stat.h> /* stat */
#include <stdio.h>    /* snprintf */

#include <utils.h>
#include <watch.h>
#include <sys/inotify.h>

/**
 * Convert the inotify watch mask to the kqueue event filter flags.
 *
 * @param[in] flags An inotify watch mask.
 * @param[in] wf    A kqueue watch internal flags.
 * @return Converted kqueue event filter flags.
 **/
uint32_t
inotify_to_kqueue (uint32_t flags, watch_flags_t wf)
{
    uint32_t result = 0;

    if (!(S_ISREG (wf) || S_ISDIR (wf) || S_ISLNK (wf))) {
        return result;
    }
    if (flags & IN_ATTRIB)
        result |= NOTE_ATTRIB;
    if (flags & IN_MODIFY && S_ISREG (wf))
        result |= NOTE_WRITE;
    if (!(wf & WF_ISSUBWATCH)) {
        if (S_ISDIR (wf)) {
            result |= NOTE_WRITE;
        }
        if (flags & IN_ATTRIB && S_ISREG (wf))
            result |= NOTE_LINK;
        if (flags & IN_MOVE_SELF)
            result |= NOTE_RENAME;
        result |= NOTE_DELETE | NOTE_REVOKE;
    }
    return result;
}

/**
 * Convert the kqueue event filter flags to the inotify watch mask.
 *
 * @param[in] flags A kqueue filter flags.
 * @param[in] wf    A kqueue watch internal flags.
 * @return Converted inotify watch mask.
 **/
uint32_t
kqueue_to_inotify (uint32_t flags, watch_flags_t wf)
{
    uint32_t result = 0;

    if (flags & NOTE_ATTRIB ||                /* attribute changes */
        (flags & (NOTE_LINK | NOTE_DELETE) && /* link number changes */
         S_ISREG (wf) && !(wf & WF_ISSUBWATCH)))
        result |= IN_ATTRIB;

    if (flags & NOTE_WRITE && S_ISREG (wf))
        result |= IN_MODIFY;

    /* Do not issue IN_DELETE_SELF if links still exist */
    if (flags & NOTE_DELETE && !(wf & WF_ISSUBWATCH) &&
        (wf & WF_DELETED || !S_ISREG (wf)))
        result |= IN_DELETE_SELF;

    if (flags & NOTE_RENAME && !(wf & WF_ISSUBWATCH))
        result |= IN_MOVE_SELF;

    if (flags & NOTE_REVOKE && !(wf & WF_ISSUBWATCH))
        result |= IN_UNMOUNT;

    /* IN_ISDIR flag for subwatches is set in the enqueue_event routine */
    if ((result & (IN_ATTRIB | IN_OPEN | IN_ACCESS | IN_CLOSE))
        && S_ISDIR (wf) && !(wf & WF_ISSUBWATCH)) {
        result |= IN_ISDIR;
    }

    return result;
}

/* struct kevent is declared slightly differently on the different BSDs.
 * This macros will help to avoid cast warnings on the supported platforms. */
#if defined (__NetBSD__)
#define PTR_TO_UDATA(X) ((intptr_t)X)
#else
#define PTR_TO_UDATA(X) (X)
#endif

/**
 * Register vnode kqueue watch in kernel kqueue(2) subsystem
 *
 * @param[in] w      A pointer to a watch
 * @param[in] fflags A filter flags in kqueue format
 * @return 1 on success, -1 on error and 0 if no events have been registered
 **/
int
watch_register_event (watch *w, uint32_t fflags)
{
    assert (w != NULL);
    int kq = w->iw->wrk->kq;
    assert (kq != -1);

    struct kevent ev;

    EV_SET (&ev,
            w->fd,
            EVFILT_VNODE,
            EV_ADD | EV_ENABLE | EV_CLEAR,
            fflags,
            0,
            PTR_TO_UDATA (w));

    return kevent (kq, &ev, 1, NULL, 0, NULL);
}

/**
 * Opens a file descriptor of kqueue watch
 *
 * @param[in] dirfd A filedes of parent directory or AT_FDCWD.
 * @param[in] path  A pointer to filename
 * @param[in] flags A watch flags in inotify format
 * @return A file descriptor of opened kqueue watch
 **/
int
watch_open (int dirfd, const char *path, uint32_t flags)
{
    assert (path != NULL);

    int openflags = O_NONBLOCK;
    openflags |= O_EVTONLY;
    openflags |= O_CLOEXEC;
    if (flags & IN_DONT_FOLLOW) {
        openflags |= O_SYMLINK;
    }
    if (flags & IN_ONLYDIR) {
        openflags |= O_DIRECTORY;
    }

    int fd = openat (dirfd, path, openflags);
    if (fd == -1) {
        return -1;
    }

    return fd;
}

/**
 * Initialize a watch.
 *
 * @param[in] iw;        A backreference to parent #i_watch.
 * @param[in] watch_type The type of the watch.
 * @param[in] fd         A file descriptor of a watched entry.
 * @param[in] st         A stat structure of watch.
 * @return A pointer to a watch on success, NULL on failure.
 **/
watch *
watch_init (i_watch *iw, watch_type_t watch_type, int fd, struct stat *st)
{
    assert (iw != NULL);
    assert (fd != -1);

    watch_flags_t wf = watch_type != WATCH_USER ? WF_ISSUBWATCH : 0;
    wf |= st->st_mode & S_IFMT;

    uint32_t fflags = inotify_to_kqueue (iw->flags, wf);
    /* Skip watches with empty kqueue filter flags */
    if (fflags == 0) {
        return NULL;
    }

    watch *w = calloc (1, sizeof (struct watch));
    if (w == NULL) {
        perror_msg ("Failed to allocate watch");
        return NULL;
    }

    w->iw = iw;
    w->fd = fd;
    w->flags = wf;
    w->refcount = 0;
    /* Inode number obtained via fstat call cannot be used here as it
     * differs from readdir`s one at mount points. */
    w->inode = st->st_ino;

    if (watch_register_event (w, fflags) == -1) {
        free (w);
        return NULL;
    }

    return w;
}

/**
 * Free a watch and all the associated memory.
 *
 * @param[in] w A pointer to a watch.
 **/
void
watch_free (watch *w)
{
    assert (w != NULL);
    if (w->fd != -1) {
        close (w->fd);
    }
    free (w);
}
