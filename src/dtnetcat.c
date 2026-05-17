#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include <unistd.h>

#include <bp.h>
#include <bp_admin.h>
#include <ion.h>
#include <platform.h>
#include <psm.h>
#include <sdr.h>

#include "compat.h"

#define BUFSIZE 16384

static bool dflag; // Detached, no stdin
static bool kflag; // Listen mode accepts > 1 non-anonymous sources
static bool lflag; // Listen mode
static char *sflag = NULL; // Source EID for bundles we send

static int recvcount, recvlimit;
static int timeout = -1;
static const char *source_eid = NULL;
static char *dest_eid = NULL;

struct zco_entry {
    Object zco;
    size_t obj_length;
    STAILQ_ENTRY(zco_entry) entries;
};
static STAILQ_HEAD(zco_buflist_head, zco_entry) head = STAILQ_HEAD_INITIALIZER(
    head
);

static _Atomic uint64_t last_activity_ms = 0;
static atomic_bool stopped_recv = false; // Interrupt or recvlimit reached
static atomic_bool has_dest = false;
static bool added_eid = false;
static pthread_t main_thread_id;
static pthread_t recv_thread_id;

static ReqAttendant attendant = {0};
static BpSAP sap = NULL;
static Sdr sdr = NULL;
static pthread_mutex_t sdr_mutex = PTHREAD_MUTEX_INITIALIZER;

static void handle_empty(int);
static void handle_interrupt(int);
static void cleanup(void);
static uint64_t get_now_ms(void);
static void update_activity(void);
static bool passed_timeout(void);
static bool drain(Object);
static void send_loop(void);
static void *recv_loop(void *);
static bool is_valid_ion_eid(const char *);
static bool is_null_or_invalid_eid(const char *);
static void validate_eid_or_serv_nbr(const char *);
static const char *resolve_source_eid(const char *, char *, char *, size_t);
static void usage(bool);

int main(int argc, char *argv[]) {
    int ch;
    const char *errstr = NULL;

    dtnc_setprogname(argv[0]);
    main_thread_id = pthread_self();

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        err(EXIT_FAILURE, "could not ignore SIGPIPE");
    }
    struct sigaction sa = {0};
    sa.sa_handler = &handle_empty;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        err(EXIT_FAILURE, "could not change action of SIGUSR1");
    }
    sa.sa_handler = &handle_interrupt;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        err(EXIT_FAILURE, "could not change action of SIGINT");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        err(EXIT_FAILURE, "could not change action of SIGTERM");
    }

    while ((ch = getopt(argc, argv, "dkls:W:w:")) != -1) {
        switch (ch) {
            case 'd':
                dflag = true;
                break;
            case 'k':
                kflag = true;
                break;
            case 'l':
                lflag = true;
                break;
            case 's':
                sflag = optarg;
                break;
            case 'W':
                recvlimit = (int)strtonum(optarg, 1, INT_MAX, &errstr);
                if (errstr != NULL) {
                    errx(EXIT_FAILURE, "receive limit %s: %s", errstr, optarg);
                }
                break;
            case 'w':
                timeout = (int)strtonum(optarg, 0, INT_MAX / 1000, &errstr);
                if (errstr != NULL) {
                    errx(EXIT_FAILURE, "timeout %s: %s", errstr, optarg);
                }
                timeout *= 1000;
                break;
            default:
                usage(true);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc == 1) {
        if (lflag) {
            source_eid = argv[0];
        } else {
            dest_eid = strdup(argv[0]);
            atomic_store(&has_dest, true);
        }
    } else {
        usage(true);
    }

    if (lflag && (sflag != NULL)) {
        errx(EXIT_FAILURE, "cannot use -s and -l");
    }
    if (!lflag && kflag) {
        errx(EXIT_FAILURE, "must use -l with -k");
    }

    if (lflag) {
        validate_eid_or_serv_nbr(argv[0]);
    } else if (sflag != NULL) {
        validate_eid_or_serv_nbr(sflag);
    }

    if (kflag) {
        // This matches `nc -klu`.
        // We could make -k less strict and send to the last src EID we saw
        // that wasn't a null EID (to kinda simulate connections in TCP).
        // But that involves protecting against race conditions
        // since we'd need to write to dest_eid, so put it on the back burner.
        dflag = true;
    }

    if (bp_attach() < 0) {
        errx(EXIT_FAILURE, "could not attach to BP");
    }

    sdr = bp_get_sdr();
    if (sdr == NULL) {
        warnx("could not obtain handle for SDR");
        cleanup();
        return EXIT_FAILURE;
    }

    if (ionStartAttendant(&attendant) == -1) {
        warnx("could not start attendant for ZCO space acquisitions");
        cleanup();
        return EXIT_FAILURE;
    }

    uvast fqnn = getOwnFqnn();
    char fqnn_buf[FQN_MAX_LENGTH];
    putFqn(fqnn_buf, fqnn);
    char eid_buf[64]; // Buffer to fill in source_eid

    if (!lflag && sflag == NULL) {
        // TODO: once bp_admin API lets you see what schemes are available,
        // only try this if ipn can be used.
        uint32_t service_nbr = 0;
        if (fqnn != 0) {
            for (int i = 0; i < 10; i++) {
                // RFC 9758 reserves three ranges for private use.
                // Use the largest range to match how OSes treat ports.
                service_nbr =
                    0x10000 + arc4random_uniform(0xFFFFFFFF - 0x10000 + 1);
                snprintf(
                    eid_buf,
                    sizeof(eid_buf),
                    "ipn:%s.%" PRIu32,
                    fqnn_buf,
                    service_nbr
                );
                // add_endpoint() returning 0 here means duplicate
                // since our code creates a valid EID.
                int add_eid_rv = add_endpoint(eid_buf, DiscardBundle, NULL);
                if (add_eid_rv == -1) {
                    continue;
                }
                if (bp_open(eid_buf, &sap) == 0) {
                    added_eid = true;
                    source_eid = eid_buf;
                    break;
                } else if (add_eid_rv == 1) {
                    (void)remove_endpoint(eid_buf);
                }
            }
            if (source_eid == NULL) {
                warnx("could not find a valid service number in 10 attempts");
                cleanup();
                return EXIT_FAILURE;
            }
        } else {
            // If FQNN is 0, use Null ipn URI
            source_eid = "dtn:none";
        }
    } else {
        if (lflag) {
            source_eid =
                resolve_source_eid(argv[0], fqnn_buf, eid_buf, sizeof(eid_buf));
            if (is_null_or_invalid_eid(source_eid)) {
                warnx("cannot listen on null or invalid EID");
                cleanup();
                return EXIT_FAILURE;
            }
        } else if (sflag != NULL) {
            source_eid =
                resolve_source_eid(sflag, fqnn_buf, eid_buf, sizeof(eid_buf));
        }
        assert(source_eid != NULL);
        if (!is_null_or_invalid_eid(source_eid)) {
            // add_endpoint() can return 0 for invalid EIDs,
            // but bp_open() will catch that.
            switch (add_endpoint(source_eid, DiscardBundle, NULL)) {
                case 1:
                    added_eid = true;
                    break;
                case -1:
                    warnx("could not add source endpoint");
                    cleanup();
                    return EXIT_FAILURE;
                default:
                    break;
            }
            if (bp_open(source_eid, &sap) == -1) {
                warnx("could not open source endpoint");
                cleanup();
                return EXIT_FAILURE;
            }
        } else if (!is_valid_ion_eid(source_eid)) {
            warnx("cannot use invalid source EID");
            cleanup();
            return EXIT_FAILURE;
        }
    }

    if (dest_eid != NULL && is_null_or_invalid_eid(dest_eid)) {
        warnx("cannot send to null or invalid EID");
        cleanup();
        return EXIT_FAILURE;
    }

    update_activity();
    if (sap != NULL) {
        int s = pthread_create(&recv_thread_id, NULL, &recv_loop, NULL);
        if (s != 0) {
            warnc(s, "pthread_create");
            cleanup();
            return EXIT_FAILURE;
        }
    }
    send_loop();
    if (sap != NULL) {
        pthread_join(recv_thread_id, NULL);
    }
    cleanup();

    return EXIT_SUCCESS;
}

static void handle_empty(int sig) {
    (void)sig;
}

static void handle_interrupt(int sig) {
    (void)sig;
    atomic_store(&stopped_recv, true);
    pthread_kill(main_thread_id, SIGUSR1);
    if (sap != NULL) {
        bp_interrupt(sap);
        pthread_kill(recv_thread_id, SIGUSR1);
    }
}

static void cleanup(void) {
    while (!STAILQ_EMPTY(&head)) {
        struct zco_entry *n = STAILQ_FIRST(&head);

        if (sdr_begin_xn(sdr) == 0) {
            warnx("could not initiate a SDR transaction");
            break;
        }
        zco_destroy(sdr, n->zco);
        if (sdr_end_xn(sdr) == -1) {
            warnx("SDR transaction failed");
            break;
        }

        STAILQ_REMOVE_HEAD(&head, entries);
        free(n);
    }
    if (attendant.semaphore != 0) {
        ionStopAttendant(&attendant);
    }
    bp_close(sap);
    if (added_eid && (remove_endpoint(source_eid) == -1)) {
        warnx("could not remove registered endpoint %s", source_eid);
    }
    bp_detach();
    if (dest_eid != NULL) {
        free(dest_eid);
    }
    int ec = pthread_mutex_destroy(&sdr_mutex);
    if (ec != 0) {
        warnc(ec, "could not destroy SDR lock");
    }
}

static uint64_t get_now_ms(void) {
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static void update_activity(void) {
    atomic_store(&last_activity_ms, get_now_ms());
}

static bool passed_timeout(void) {
    if (timeout == -1) {
        return false;
    }
    if (!atomic_load(&has_dest)) {
        return false;
    }
    uint64_t now = get_now_ms();
    uint64_t last = atomic_load(&last_activity_ms);
    return (now - last) >= (uint64_t)timeout;
}

// Write the conents of zco to BP.
// Caller should be holding onto sdr_mutex.
// Returns true if a failure happened, false otherwise.
static bool drain(Object zco) {
    // TODO: don't hardcode lifespan, classOfService, custodySwitch
    switch (bp_send(
        sap,
        dest_eid,
        NULL,
        86400,
        BP_STD_PRIORITY,
        NoCustodyRequested,
        0,
        0,
        NULL,
        zco,
        NULL
    ))
    {
        case 1:
            return false;
        case 0:
            warnx("could not send bundle");
            if (sdr_begin_xn(sdr) == 0) {
                warnx("could not initiate a SDR transaction");
                return true;
            }
            zco_destroy(sdr, zco);
            if (sdr_end_xn(sdr) == -1) {
                warnx("SDR transaction failed");
            }
            return true;
        case -1:
            warnx("system error occurred while sending bundle");
            return true;
        default:
            warnx("unexpected value returned by bp_send()");
            return false;
    }
}

// Handles the stdin -> DTN path
static void send_loop(void) {
    if (dflag) {
        return;
    }

    unsigned char stdinbuf[BUFSIZE];
    size_t stdinbufpos = 0;
    size_t num = 0;

    struct pollfd pfd[1];
    pfd[0].fd = STDIN_FILENO;
    pfd[0].events = POLLIN;

    while (true) {
        if (atomic_load(&stopped_recv) || pfd[0].fd == -1) {
            return;
        }

        // Read from stdin if dest_eid is known
        // or we can still buffer from stdin.
        pfd[0].events = 0;
        if (atomic_load(&has_dest)) {
            pfd[0].events = POLLIN;
            num = BUFSIZE;
        } else if (stdinbufpos < BUFSIZE) {
            pfd[0].events = POLLIN;
            num = BUFSIZE - stdinbufpos;
        }

        int num_fds = poll(pfd, 1, timeout);
        if (num_fds == -1) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            warn("polling error");
            return;
        }

        // Timeout happened
        if (num_fds == 0) {
            if (passed_timeout()) {
                atomic_store(&stopped_recv, true);
                if (sap != NULL) {
                    bp_interrupt(sap);
                    pthread_kill(recv_thread_id, SIGUSR1);
                }
                return;
            }
            continue;
        }

        // Treat socket error conditions
        if (pfd[0].revents & (POLLERR | POLLNVAL)) {
            pfd[0].fd = -1;
            continue;
        }

        // Try to read from stdin
        if (pfd[0].revents & POLLIN) {
            ssize_t ret = read(pfd[0].fd, stdinbuf, num);
            if (ret == -1 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else if (ret == 0 || ret == -1) {
                pfd[0].fd = -1;
                continue;
            }

            update_activity();

            pthread_mutex_lock(&sdr_mutex);
            if (sdr_begin_xn(sdr) == 0) {
                warnx("could not initiate a SDR transaction");
                pthread_mutex_unlock(&sdr_mutex);
                return;
            }
            Object payload_block =
                sdr_insert(sdr, (char *)stdinbuf, (size_t)ret);
            if (sdr_end_xn(sdr) == -1) {
                warnx("SDR transaction failed");
                pthread_mutex_unlock(&sdr_mutex);
                return;
            }

            Object bundle_zco = ionCreateZco(
                ZcoSdrSource,
                payload_block,
                0,
                ret,
                BP_STD_PRIORITY,
                0,
                ZcoOutbound,
                &attendant
            );
            if (bundle_zco == 0 || bundle_zco == (Object)ERROR) {
                if (sdr_begin_xn(sdr) == 0) {
                    warnx("could not initiate a SDR transaction to clean");
                    pthread_mutex_unlock(&sdr_mutex);
                    return;
                }
                sdr_free(sdr, payload_block);
                if (sdr_end_xn(sdr) == -1) {
                    warnx("SDR transaction to clean SDR failed");
                    pthread_mutex_unlock(&sdr_mutex);
                    return;
                }
                warnx("could not create ZCO");
                pthread_mutex_unlock(&sdr_mutex);
                return;
            }

            if (atomic_load(&has_dest)) {
                bool should_ret = drain(bundle_zco);
                if (should_ret) {
                    pfd[0].fd = -1;
                }
            } else {
                struct zco_entry *n = malloc(sizeof(struct zco_entry));
                n->zco = bundle_zco;
                n->obj_length = (size_t)ret;

                STAILQ_INSERT_TAIL(&head, n, entries);
                stdinbufpos += n->obj_length;
            }
            pthread_mutex_unlock(&sdr_mutex);
        }
    }
}

// Handles the DTN -> stdout path
static void *recv_loop(void *arg) {
    (void)arg;
    BpDelivery dlv;
    unsigned char netinbuf[BUFSIZE];

    struct pollfd pfd[1];
    pfd[0].fd = STDOUT_FILENO;
    pfd[0].events = 0;

    while (true) {
        if (atomic_load(&stopped_recv)) {
            break;
        }
        int recv_timeout = BP_BLOCKING;
        if (atomic_load(&has_dest)) {
            if (timeout != -1) {
                recv_timeout = timeout / 1000;
            }
        }
        if (bp_receive(sap, &dlv, recv_timeout) == -1) {
            warnx("could not receive bundle");
            return NULL;
        }
        if (dlv.result == BpReceptionInterrupted) {
            // handle_interrupt set stopped_recv to true
            bp_release_delivery(&dlv, 1);
            continue;
        } else if (dlv.result == BpReceptionTimedOut) {
            bp_release_delivery(&dlv, 1);
            if (passed_timeout()) {
                atomic_store(&stopped_recv, true);
                pthread_kill(main_thread_id, SIGUSR1);
                break;
            }
            continue;
        } else if (dlv.result == BpEndpointStopped) {
            bp_release_delivery(&dlv, 1);
            break;
        } else if (dlv.result == BpPayloadPresent) {
            if (!atomic_load(&has_dest)) {
                if (!is_null_or_invalid_eid(dlv.bundleSourceEid)) {
                    dest_eid = strdup(dlv.bundleSourceEid);
                    if (dest_eid == NULL) {
                        bp_release_delivery(&dlv, 1);
                        warn("not enough memory to copy destination EID");
                        return NULL;
                    }

                    pthread_mutex_lock(&sdr_mutex);
                    while (!STAILQ_EMPTY(&head)) {
                        struct zco_entry *n = STAILQ_FIRST(&head);
                        bool should_ret = drain(n->zco);
                        if (should_ret) {
                            pthread_mutex_unlock(&sdr_mutex);
                            return NULL;
                        }
                        STAILQ_REMOVE_HEAD(&head, entries);
                        free(n);
                    }
                    pthread_mutex_unlock(&sdr_mutex);

                    atomic_store(&has_dest, true);
                    pthread_kill(main_thread_id, SIGUSR1);
                }
            } else if (!kflag && strcmp(dlv.bundleSourceEid, dest_eid) != 0) {
                bp_release_delivery(&dlv, 1);
                continue;
            }

            update_activity();

            if (recvlimit > 0 && ++recvcount >= recvlimit) {
                atomic_store(&stopped_recv, true);
                pthread_kill(main_thread_id, SIGUSR1);
            }

            ZcoReader reader;

            pthread_mutex_lock(&sdr_mutex);
            if (sdr_begin_xn(sdr) == 0) {
                bp_release_delivery(&dlv, 1);
                pthread_mutex_unlock(&sdr_mutex);
                warnx("could not initiate a SDR transaction");
                return NULL;
            }
            vast bundle_len_remaining = zco_source_data_length(sdr, dlv.adu);
            sdr_exit_xn(sdr);

            zco_start_receiving(dlv.adu, &reader);
            while (bundle_len_remaining > 0) {
                vast read_len = bundle_len_remaining < BUFSIZE
                    ? bundle_len_remaining
                    : BUFSIZE;
                if (sdr_begin_xn(sdr) == 0) {
                    warnx("could not initiate a SDR transaction");
                    break;
                }
                vast num_copied = zco_receive_source(
                    sdr,
                    &reader,
                    read_len,
                    (char *)netinbuf
                );
                if (sdr_end_xn(sdr) == -1 || num_copied <= 0) {
                    warnx("error extracting data from ZCO");
                    break;
                }

                ssize_t written = 0;
                pfd[0].events = POLLOUT;
                while (written < num_copied) {
                    int num_fds = poll(pfd, 1, -1);
                    if (num_fds == -1) {
                        if (errno == EINTR || errno == EAGAIN) {
                            continue;
                        }
                        bp_release_delivery(&dlv, 1);
                        pthread_mutex_unlock(&sdr_mutex);
                        warn("polling error");
                        return NULL;
                    }

                    // Timeout happened
                    if (num_fds == 0) {
                        bp_release_delivery(&dlv, 1);
                        pthread_mutex_unlock(&sdr_mutex);
                        return NULL;
                    }

                    // Treat socket error conditions
                    if (pfd[0].revents & (POLLERR | POLLNVAL)) {
                        bp_release_delivery(&dlv, 1);
                        pthread_mutex_unlock(&sdr_mutex);
                        return NULL;
                    }

                    if (pfd[0].revents & POLLOUT) {
                        ssize_t ret = write(
                            pfd[0].fd,
                            netinbuf + written,
                            (size_t)(num_copied - written)
                        );
                        if (ret == -1) {
                            if (errno == EAGAIN || errno == EINTR) {
                                continue;
                            }
                            bp_release_delivery(&dlv, 1);
                            pthread_mutex_unlock(&sdr_mutex);
                            return NULL;
                        }
                        written += ret;
                    }
                }
                bundle_len_remaining -= num_copied;
            }
            bp_release_delivery(&dlv, 1);
            pthread_mutex_unlock(&sdr_mutex);
        }
    }
    return NULL;
}

// Returns true if ION can parse the EID, false otherwise.
static bool is_valid_ion_eid(const char *str) {
    MetaEid meta_eid = {0};
    VScheme *vscheme = NULL;
    PsmAddress vscheme_elt;
    if (parseEidString(str, &meta_eid, &vscheme, &vscheme_elt) == 0) {
        return false;
    }
    return true;
}

// Returns true if `str` is likely a null EID,
// is an ipn URI with a zero FQNN and non-zero service number,
// or cannot be parsed by ION.
static bool is_null_or_invalid_eid(const char *str) {
    MetaEid meta_eid = {0};
    VScheme *vscheme = NULL;
    PsmAddress vscheme_elt;

    if (parseEidString(str, &meta_eid, &vscheme, &vscheme_elt) == 0) {
        return true;
    } else if (meta_eid.nullEndpoint == 1) {
        return true;
    } else if (meta_eid.schemeCodeNbr == ipn && meta_eid.elementNbr == 0) {
        return true;
    }
    return false;
}

static void validate_eid_or_serv_nbr(const char *str) {
    const char *errstr;
    if (strchr(str, ':') != NULL) {
        // Assume not a number
        return;
    }
    (void)strtonum(str, 0, UINT32_MAX, &errstr);
    if (errstr != NULL) {
        errx(EXIT_FAILURE, "service number %s: %s", errstr, str);
    }
}

// Use after validating `str` with validate_eid_or_serv_nbr().
static const char *resolve_source_eid(
    const char *str,
    char *fqnn_buf,
    char *buf,
    size_t buflen
) {
    if (strchr(str, ':') != NULL) {
        return str;
    }
    uint32_t service_nbr = (uint32_t)strtonum(str, 0, UINT32_MAX, NULL);
    (void)snprintf(buf, buflen, "ipn:%s.%" PRIu32, fqnn_buf, service_nbr);
    return buf;
}

static void usage(bool should_exit) {
    const char *p = dtnc_getprogname();
    (void)fprintf(
        stderr,
        // clang-format off
"usage: %s [-d] [-s source] [-W recvlimit] [-w timeout] destination_eid\n"
"       %s [-dkl] [-W recvlimit] [-w timeout] source_eid\n",
        // clang-format on
        p,
        p
    );
    if (should_exit) {
        exit(EXIT_FAILURE);
    }
}
