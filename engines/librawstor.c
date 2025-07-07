/*
 * null engine
 *
 * IO engine that doesn't do any real IO transfers, it just pretends to.
 * The main purpose is to test fio itself.
 *
 * It also can act as external C++ engine - compiled with:
 *
 * g++ -O2 -g -shared -rdynamic -fPIC -o cpp_null null.c \
 *	-include ../config-host.h -DFIO_EXTERNAL_ENGINE
 *
 * to test it execute:
 *
 * LD_LIBRARY_PATH=./engines ./fio examples/cpp_null.fio
 *
 */
#include <stdlib.h>
#include <assert.h>

#include <rawstor.h>

#include "../fio.h"

struct null_data {
	struct io_u **io_us;
	int queued;
	int events;
};

static struct io_u *null_event(struct null_data *nd, int event)
{
	return nd->io_us[event];
}

static int null_getevents(struct null_data *nd, unsigned int min_events,
			  unsigned int fio_unused max,
			  const struct timespec fio_unused *t)
{
	int ret = 0;

	if (min_events) {
		ret = nd->events;
		nd->events = 0;
	}

	return ret;
}

static void null_queued(struct thread_data *td, struct null_data *nd)
{
	struct timespec now;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	for (int i = 0; i < nd->queued; i++) {
		struct io_u *io_u = nd->io_us[i];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);
	}
}

static int null_commit(struct thread_data *td, struct null_data *nd)
{
	if (!nd->events) {
		null_queued(td, nd);

#ifndef FIO_EXTERNAL_ENGINE
		io_u_mark_submit(td, nd->queued);
#endif
		nd->events = nd->queued;
		nd->queued = 0;
	}

	return 0;
}

static enum fio_q_status null_queue(struct thread_data *td,
				    struct null_data *nd, struct io_u *io_u)
{
	fio_ro_check(td, io_u);

	if (td->io_ops->flags & FIO_SYNCIO)
		return FIO_Q_COMPLETED;
	if (nd->events)
		return FIO_Q_BUSY;

	nd->io_us[nd->queued++] = io_u;
	return FIO_Q_QUEUED;
}

static int null_open(struct null_data fio_unused *nd,
		     struct fio_file fio_unused *f)
{
	return 0;
}

static void null_cleanup(struct null_data *nd)
{
	if (nd) {
		free(nd->io_us);
		free(nd);
	}
}

static struct null_data *null_init(struct thread_data *td)
{
	struct null_data *nd;
	nd = malloc(sizeof(*nd));

	memset(nd, 0, sizeof(*nd));

	if (td->o.iodepth != 1) {
		nd->io_us = calloc(td->o.iodepth, sizeof(struct io_u *));
		td->io_ops->flags |= FIO_ASYNCIO_SETS_ISSUE_TIME;
	} else
		td->io_ops->flags |= FIO_SYNCIO;

	td_set_ioengine_flags(td);
	return nd;
}

static struct io_u *fio_null_event(struct thread_data *td, int event)
{
	return null_event(td->io_ops_data, event);
}

static int fio_null_getevents(struct thread_data *td, unsigned int min_events,
			      unsigned int max, const struct timespec *t)
{
	struct null_data *nd = td->io_ops_data;
	return null_getevents(nd, min_events, max, t);
}

static int fio_null_commit(struct thread_data *td)
{
	return null_commit(td, td->io_ops_data);
}

static enum fio_q_status fio_null_queue(struct thread_data *td,
					struct io_u *io_u)
{
	return null_queue(td, td->io_ops_data, io_u);
}

static int fio_null_open(struct thread_data *td, struct fio_file *f)
{
	return null_open(td->io_ops_data, f);
}

static void fio_null_cleanup(struct thread_data *td)
{
	null_cleanup(td->io_ops_data);
}

static int fio_null_init(struct thread_data *td)
{
	td->io_ops_data = null_init(td);
	assert(td->io_ops_data);
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "librawstor",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_null_queue,
	.commit		= fio_null_commit,
	.getevents	= fio_null_getevents,
	.event		= fio_null_event,
	.init		= fio_null_init,
	.cleanup	= fio_null_cleanup,
	.open_file	= fio_null_open,
	.flags		= FIO_DISKLESSIO | FIO_FAKEIO,
};

static void fio_init fio_rawstor_register(void)
{
	rawstor_initialize(NULL);
	register_ioengine(&ioengine);
}

static void fio_exit fio_rawstor_unregister(void)
{
	unregister_ioengine(&ioengine);
	rawstor_terminate();
}
