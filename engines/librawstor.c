/*
 * librawstor engine
 *
 * IO engine that uses the librawstor interface.
 *
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <rawstor.h>

#include "../fio.h"
#include "../optgroup.h"

// rawstor >= 0.2.0
#if (RAWSTOR_VERSION_MAJOR == 0 && RAWSTOR_VERSION_MINOR >= 2) || \
    RAWSTOR_VERSION_MAJOR >= 1
#define FF_MULTIQUEUE
#endif


struct rawstor_iou {
    int complete;
    int seen;
};


struct rawstor_data {
#ifdef FF_MULTIQUEUE
    RawIOQueue *queue;
#endif
    int opened_files;
    struct io_u **events;
    int queued;
};


struct rawstor_options {
    struct thread_data *td;
};


static struct fio_option options[] = {
    {
        .name = NULL,
    },
};


static struct io_u *fio_rawstor_event(struct thread_data *td, int event) {
    struct rawstor_data *rd = td->io_ops_data;
    return rd->events[event];
}


static int fio_rawstor_getevents(
    struct thread_data *td, unsigned int min,
    unsigned int max, const struct timespec *t)
{
    struct rawstor_data *rd = td->io_ops_data;
    struct io_u *io_u;
    struct rawstor_iou *riou;
    int i;
    int res;
    unsigned int events = 0;

    while (true) {
        io_u_qiter(&td->io_u_all, io_u, i) {
            riou = io_u->engine_data;
            if (riou->seen) {
                continue;
            }

            if (riou->complete) {
                riou->seen = 1;
                --rd->queued;
                rd->events[events++] = io_u;
                if (events >= max) {
                    break;
                }

            }
        }

        if (events >= min) {
            return events;
        }

#ifdef FF_MULTIQUEUE
        res = rawio_wait(rd->queue);
#else
        res = rawstor_wait();
#endif

        if (res < 0) {
            log_err("rawstor: wait failed: %s\n", strerror(-res));
            td_verror(td, -res, "xfer");
            break;
        }
    }

    return 0;
}


static int io_callback(
    RawstorObject *object, size_t size, size_t res, int error, void *data)
{
    struct io_u *io_u = data;
    struct rawstor_iou *riou = io_u->engine_data;

    if (error) {
        io_u->error = error;
        io_u->resid = io_u->xfer_buflen;
    } else {
        io_u->error = 0;
    }

    riou->complete = 1;

    return 0;
}


static enum fio_q_status fio_rawstor_queue(
    struct thread_data *td,
    struct io_u *io_u)
{
    struct rawstor_data *rd = td->io_ops_data;
    RawstorObject *object = FILE_ENG_DATA(io_u->file);
    struct rawstor_iou *riou = io_u->engine_data;
    int ret;

    fio_ro_check(td, io_u);

    riou->complete = 0;
    riou->seen = 0;

    if (io_u->ddir == DDIR_READ) {
        ret = rawstor_object_pread(
            object,
            io_u->xfer_buf, io_u->xfer_buflen, io_u->offset,
            io_callback, io_u);
    } else if (io_u->ddir == DDIR_WRITE) {
        ret = rawstor_object_pwrite(
            object,
            io_u->xfer_buf, io_u->xfer_buflen, io_u->offset,
            io_callback, io_u);
    } else if (io_u->ddir == DDIR_TRIM) {
        if (rd->queued) {
            return FIO_Q_BUSY;
        }

        /**
         * TODO: Implement trim.
         */

        return FIO_Q_COMPLETED;
    } else {
        if (rd->queued) {
            return FIO_Q_BUSY;
        }

        /**
         * TODO: Implement sync.
         */

        return FIO_Q_COMPLETED;
    }

    if (ret < 0) {
        io_u->error = -ret;
        td_verror(td, io_u->error, "xfer");
        log_err("rawstor: failed to queue xfer: %s\n", strerror(-ret));
        return FIO_Q_COMPLETED;
    }

    rd->queued++;

    return FIO_Q_QUEUED;
}


static int fio_rawstor_open(struct thread_data *td, struct fio_file *f) {
    int res;
    RawstorObject *object;
    struct rawstor_data *rd = td->io_ops_data;

    if (rd->opened_files == 0) {
        res = rawstor_initialize(NULL);
        if (res) {
            log_err(
                "rawstor: rawstor_initialize() failed: %s\n", strerror(-res));
            return 1;
        }
        ++rd->opened_files;
    }

#ifdef FF_MULTIQUEUE
    res = rawstor_object_open(rd->queue, f->file_name, &object);
#else
    res = rawstor_object_open(f->file_name, &object);
#endif
    if (res) {
        td_verror(td, -res, "rawstor_open");
        if (rd->opened_files == 0) {
            rawstor_terminate();
        }
        return 1;
    }

    ++rd->opened_files;
    FILE_SET_ENG_DATA(f, object);

    return 0;
}


static int fio_rawstor_close(
    struct thread_data fio_unused *td,
    struct fio_file *f)
{
    struct rawstor_data *rd = td->io_ops_data;
    RawstorObject *object = FILE_ENG_DATA(f);

    int res = rawstor_object_close(object);
    if (res) {
        td_verror(td, res, "rawstor_object_close");
        return 1;
    }

    --rd->opened_files;
    if (rd->opened_files == 0) {
        rawstor_terminate();
    }

    return 0;
}


static int fio_rawstor_invalidate(struct thread_data *td, struct fio_file *f) {
    return 0;
}


static int fio_rawstor_io_u_init(struct thread_data *td, struct io_u *io_u) {
    struct rawstor_iou *riou;

    riou = malloc(sizeof(*riou));
    if (riou == NULL) {
        td_verror(td, errno, "malloc");
        return 1;
    }

    io_u->engine_data = riou;

    return 0;
}


static void fio_rawstor_io_u_free(struct thread_data *td, struct io_u *io_u) {
    struct rawstor_iou *riou = io_u->engine_data;

    if (riou) {
        io_u->engine_data = NULL;
        free(riou);
    }
}


static void fio_rawstor_cleanup(struct thread_data *td) {
    struct rawstor_data *rd = td->io_ops_data;

    if (rd) {
#ifdef FF_MULTIQUEUE
        rawio_queue_delete(rd->queue);
#endif
        free(rd->events);
        free(rd);
    }
}


static int fio_rawstor_setup(struct thread_data *td) {
    int res;
    struct RawstorObjectSpec spec;
    struct fio_file *f;
    uint32_t i;

    res = rawstor_initialize(NULL);
    if (res) {
        log_err(
            "rawstor: rawstor_initialize() failed: %s\n", strerror(-res));
        return 1;
    }

    for (i = 0; i < td->o.nr_files; i++) {
        f = td->files[i];

        res = rawstor_object_spec(f->file_name, &spec);
        if (res) {
            td_verror(td, -res, "rawstor_object_spec");
            return 1;
        }

        f->real_file_size = spec.size;
    }

    rawstor_terminate();

    return 0;
}


static int fio_rawstor_init(struct thread_data *td) {
#ifdef FF_MULTIQUEUE
    int res;
#endif

    struct rawstor_data *rd = malloc(sizeof(*rd));
    if (rd == NULL) {
        td_verror(td, errno, "malloc");
        return 1;
    }

    *rd = (struct rawstor_data) {};

#ifdef FF_MULTIQUEUE
    res = rawio_queue_create(256, &rd->queue);
    if (res < 0) {
        free(rd);
        td_verror(td, -res, "rawio_queue_create");
        return 1;
    }
#endif

    rd->events = calloc(td->o.iodepth, sizeof(struct io_u*));

    td_set_ioengine_flags(td);

    td->io_ops_data = rd;
    return 0;
}


static struct ioengine_ops ioengine = {
    .name = "librawstor",
    .version = FIO_IOOPS_VERSION,
    .flags = FIO_ASYNCIO_SETS_ISSUE_TIME,
    .queue = fio_rawstor_queue,
    .getevents = fio_rawstor_getevents,
    .event = fio_rawstor_event,
    .setup = fio_rawstor_setup,
    .init = fio_rawstor_init,
    .cleanup = fio_rawstor_cleanup,
    .open_file = fio_rawstor_open,
    .close_file = fio_rawstor_close,
    .invalidate = fio_rawstor_invalidate,
    .io_u_init = fio_rawstor_io_u_init,
    .io_u_free = fio_rawstor_io_u_free,
    .options = options,
    .option_struct_size = sizeof(struct rawstor_options),
};


static void fio_init fio_rawstor_register(void) {
    register_ioengine(&ioengine);
}


static void fio_exit fio_rawstor_unregister(void) {
    unregister_ioengine(&ioengine);
}
