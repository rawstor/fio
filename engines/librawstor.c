/*
 * null engine
 *
 * IO engine that doesn't do any real IO transfers, it just pretends to.
 * The main purpose is to test fio itself.
 *
 * It also can act as external C++ engine - compiled with:
 *
 * g++ -O2 -g -shared -rdynamic -fPIC -o cpp_null null.c \
 *        -include ../config-host.h -DFIO_EXTERNAL_ENGINE
 *
 * to test it execute:
 *
 * LD_LIBRARY_PATH=./engines ./fio examples/cpp_null.fio
 *
 */

#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <rawstor.h>

#include "../fio.h"
#include "../optgroup.h"


struct rawstor_data {
    struct io_u **io_us;
    int queued;
    int events;
};


struct rawstor_options {
	struct thread_data *td;
	char *object_id;
	RawstorUUID object_id_uuid;
	char *ost;
};


static struct fio_option options[] = {
	{
		.name = "object_id",
		.lname = "Object id",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct rawstor_options, object_id),
		.help = "Rawstor object id",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},

	{
		.name = "ost",
		.lname = "OST host:port",
		.type = FIO_OPT_STR_STORE,
		.off1 = offsetof(struct rawstor_options, ost),
		.help = "OST host:port",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},

    {
		.name	= NULL,
	},
};


static struct io_u *null_event(struct rawstor_data *rd, int event) {
    return rd->io_us[event];
}


static int null_getevents(
    struct rawstor_data *rd, unsigned int min_events,
    unsigned int fio_unused max,
    const struct timespec fio_unused *t)
{
    int ret = 0;

    if (min_events) {
        ret = rd->events;
        rd->events = 0;
    }

    return ret;
}


static void null_queued(struct thread_data *td, struct rawstor_data *rd) {
    struct timespec now;

    if (!fio_fill_issue_time(td)) {
        return;
    }

    fio_gettime(&now, NULL);

    for (int i = 0; i < rd->queued; i++) {
        struct io_u *io_u = rd->io_us[i];

        memcpy(&io_u->issue_time, &now, sizeof(now));
        io_u_queued(td, io_u);
    }
}


static int null_commit(struct thread_data *td, struct rawstor_data *rd) {
    if (!rd->events) {
        null_queued(td, rd);

#ifndef FIO_EXTERNAL_ENGINE
        io_u_mark_submit(td, rd->queued);
#endif
        rd->events = rd->queued;
        rd->queued = 0;
    }

    return 0;
}


static enum fio_q_status null_queue(
    struct thread_data *td,
    struct rawstor_data *rd, struct io_u *io_u)
{
    fio_ro_check(td, io_u);

    if (td->io_ops->flags & FIO_SYNCIO) {
        return FIO_Q_COMPLETED;
    }

    if (rd->events) {
        return FIO_Q_BUSY;
    }

    rd->io_us[rd->queued++] = io_u;
    return FIO_Q_QUEUED;
}


static int null_open(
    struct rawstor_data fio_unused *rd,
    struct fio_file fio_unused *f)
{
    return 0;
}


static void null_cleanup(struct rawstor_data *rd) {
    if (rd) {
        free(rd->io_us);
        free(rd);
    }
}


static struct rawstor_data *null_init(struct thread_data *td) {
    struct rawstor_data *rd;
    rd = malloc(sizeof(*rd));

    memset(rd, 0, sizeof(*rd));

    if (td->o.iodepth != 1) {
        rd->io_us = calloc(td->o.iodepth, sizeof(struct io_u *));
        td->io_ops->flags |= FIO_ASYNCIO_SETS_ISSUE_TIME;
    } else {
        td->io_ops->flags |= FIO_SYNCIO;
    }

    td_set_ioengine_flags(td);
    return rd;
}


static struct io_u *fio_null_event(struct thread_data *td, int event) {
    return null_event(td->io_ops_data, event);
}


static int fio_null_getevents(
    struct thread_data *td, unsigned int min_events,
    unsigned int max, const struct timespec *t)
{
    struct rawstor_data *rd = td->io_ops_data;
    return null_getevents(rd, min_events, max, t);
}


static int fio_null_commit(struct thread_data *td) {
    return null_commit(td, td->io_ops_data);
}


static enum fio_q_status fio_null_queue(
    struct thread_data *td,
    struct io_u *io_u)
{
    return null_queue(td, td->io_ops_data, io_u);
}


static int fio_rawstor_open(struct thread_data *td, struct fio_file *f) {
	struct rawstor_options *o = td->eo;
    printf("object id = %s\n", o->object_id);
    
    return null_open(td->io_ops_data, f);
}


static int fio_rawstor_close(
    struct thread_data fio_unused *td,
    struct fio_file *f)
{
    return 0;
}


static int fio_rawstor_get_file_size(
    struct thread_data *td,
    struct fio_file *f)
{
	struct rawstor_options *o = td->eo;
    RawstorObjectSpec spec;
    RawstorUUID uuid;

    RawstorOptsOST opts = (RawstorOptsOST){
        .host = o->ost,
    };

    if (o->object_id == NULL) {
        log_err("rawstor: object_id argument is required\n");
        return 1;
    }

    if (rawstor_uuid_from_string(&uuid, o->object_id)) {
        td_verror(td, errno, "rawstor_uuid_from_string");
    }

    if (rawstor_object_spec(&opts, &uuid, &spec)) {
        td_verror(td, errno, "rawstor_object_spec");
    }

    f->real_file_size = spec.size;

    return 0;
}


static void fio_null_cleanup(struct thread_data *td) {
    null_cleanup(td->io_ops_data);
}


static int fio_null_init(struct thread_data *td) {
    td->io_ops_data = null_init(td);
    assert(td->io_ops_data);
    return 0;
}


static struct ioengine_ops ioengine = {
    .name = "librawstor",
    .version = FIO_IOOPS_VERSION,
    .queue = fio_null_queue,
    .commit = fio_null_commit,
    .getevents = fio_null_getevents,
    .event = fio_null_event,
    .init = fio_null_init,
    .cleanup = fio_null_cleanup,
    .open_file = fio_rawstor_open,
    .close_file = fio_rawstor_close,
    .get_file_size = fio_rawstor_get_file_size,
	.options = options,
	.option_struct_size	= sizeof(struct rawstor_options),
};


static void fio_init fio_rawstor_register(void) {
    rawstor_initialize(NULL);
    register_ioengine(&ioengine);
}


static void fio_exit fio_rawstor_unregister(void) {
    unregister_ioengine(&ioengine);
    rawstor_terminate();
}
