#include <sys/types.h>
#include <sys/event.h>
#include <sys/param.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <libutil.h>
#include <sysexits.h>
#include <signal.h>
#include <fcntl.h>


static void usage(void);

void spawn_restart(const char*, const char*);

int main(int argc, char* const argv[]) {
    int c, i, skip=0, kq;
    char path[1024];
    char *trigger_path = NULL;
    char *ezjail_admin = NULL;
    char *jail_base_dir = NULL;
    char *pidfile = NULL;
    struct kevent *kev;
    struct sigaction osa, sa;
    pid_t otherpid;
    struct pidfh *pfh = NULL;

    setprogname(argv[0]);

    while ((c = getopt(argc, argv, "p:a:b:t:")) != -1) {
        switch (c) {
        case 'p':
            pidfile = optarg;
        case 'a':
            ezjail_admin = optarg;
            break;
        case 'b':
            jail_base_dir = optarg;
            break;
        case 't':
            trigger_path = optarg;
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (NULL == ezjail_admin || NULL == jail_base_dir ||
            NULL == trigger_path || NULL == pidfile ||
            argc < 1)
        usage();

    if (NULL == (pfh = pidfile_open(pidfile, 0600, &otherpid))) {
        if (errno == EEXIST)
            errx(3, "process already running, pid: %d",
                 otherpid);
        err(2, "pidfile ``%s''", pidfile);
    }

    if (NULL == (kev = (struct kevent *)malloc(argc * sizeof(struct kevent))))
        err(EX_UNAVAILABLE, "malloc");

    for (i=0; i < argc; i++) {
        int fd;
        snprintf(path, 1023, "%s/%s/%s", jail_base_dir, argv[i], trigger_path);
        if(-1 == (fd = open(path, O_RDONLY | O_NONBLOCK))) {
            warnx("can't open ``%s'' for reading; ignoring  %s", path, argv[i]);
            skip++;
        } else
            EV_SET(&kev[i-skip], fd, EVFILT_VNODE,
                   EV_ADD | EV_ENABLE | EV_CLEAR, NOTE_WRITE,
                   0, (void*)argv[i]);
    }
    if (skip == argc)
        errx(EX_NOINPUT, "no triggers found");
    if (skip)
        if (NULL == (realloc(kev, (argc - skip) * sizeof(struct kevent))))
            err(EX_UNAVAILABLE, "realloc");

    if (daemon(0, 1)) err(1, NULL);

    pidfile_write(pfh);

    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (-1 == sigaction(SIGCHLD, &sa, &osa)) err(EX_OSERR, "sigaction");

    if (-1 == (kq = kqueue())) err(EX_OSERR, "kqueue");

    for(;;) {
        if (-1 == (c = kevent(kq, kev,
                              (argc - skip), kev, (argc - skip), NULL)))
            err(EX_UNAVAILABLE, "kevent");
        for (i = 0; i < c; i++) {
            if (kev[i].flags & EV_ERROR)
                warnc(kev[i].data, "%s", (char *)kev[i].udata);
            else
                spawn_restart(ezjail_admin, kev[i].udata);
        }
    }
    return 0; /* not reached */
}


void spawn_restart(const char* ezjail_admin,
                   const char* jailname) {
    switch (fork()) {
    case -1:
        err(EX_OSERR, "fork");
        break;
    case 0:
        execl(ezjail_admin, ezjail_admin, "restart",
              jailname, (char *)0);
        break;
    default:
        break;
    }
}

static void usage(void) {
    fprintf(stderr,
            "usage: %s -p pidfile -a ezjail_admin_cmd "
            "-b jail_base_dir -t trigger_path jailname1 [...]\n",
            getprogname());
    exit(EX_USAGE);
}
