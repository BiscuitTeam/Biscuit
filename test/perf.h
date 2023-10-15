#ifndef _PERF_H_
#define _PERF_H_

#ifndef USE_PERF_EVENT

#include <x86intrin.h>

#define INIT_PERF()

#define PERF(expr, count_ptr)                                         \
  do {                                                                \
    uint64_t tmp = __rdtsc ();                                        \
    expr;                                                             \
    *count_ptr = __rdtsc () - tmp;                                    \
  } while (0)

#else

static struct perf_event_attr pe;
static long fd;

static long
perf_event_open (struct perf_event_attr *hw_event, pid_t pid,
                 int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static long
init_perf (struct perf_event_attr *pe)
{
  memset (pe, 0, sizeof (struct perf_event_attr));
  pe->type = PERF_TYPE_HARDWARE;
  pe->size = sizeof (struct perf_event_attr);
  pe->config = PERF_COUNT_HW_CPU_CYCLES;
  pe->disabled = 1;
  pe->exclude_kernel = 1;
  pe->exclude_hv = 1;
  return perf_event_open (pe, 0, -1, -1, 0);
}

#define INIT_PERF()                                                 \
  do {                                                              \
    fd = init_perf (&pe);                                           \
    if (fd == -1)                                                   \
      {                                                             \
        fprintf (stderr, "Error opening leader %llx\n", pe.config); \
        exit (EXIT_FAILURE);                                        \
      }                                                             \
  } while (0)

#define PERF(expr, count_ptr)                                         \
  do {                                                                \
    ioctl (fd, PERF_EVENT_IOC_RESET, 0);                              \
    ioctl (fd, PERF_EVENT_IOC_ENABLE, 0);                             \
    expr;                                                             \
    ioctl (fd, PERF_EVENT_IOC_DISABLE, 0);                            \
    if (read (fd, count_ptr, sizeof (uint64_t)) != sizeof (uint64_t)) \
      return -1;                                                      \
  } while (0)

#endif

#endif
