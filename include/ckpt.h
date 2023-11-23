#ifndef _CKPT_H
#include <sys/time.h>

static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

static int phx_mode = 0;
static int cnt = 0;
static struct ckpt_t {
        long long t;
        const char *name;
} ckpts[32] = { { 0, NULL, }, };

//enum { COUNTER_BASE = cnt };

#define CKPT 1

#define ckpt(s) \
        if(CKPT && phx_mode) { \
                if (cnt == 0) { \
                        ckpts[0] = (struct ckpt_t) { \
                                .t = ustime(), \
                                .name = s, \
                        }; \
                } else { \
                        ckpts[cnt].t = ustime() - ckpts[0].t; \
                        ckpts[cnt].name = s; \
                } \
                cnt++; \
        }


#endif
