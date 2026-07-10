// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GOVFUZZ_AFL_FALLBACK_MAX_INPUT (1024u * 1024u)

static size_t govfuzz_read_stdin(unsigned char *buf, size_t capacity);
static int govfuzz_write_all(int fd, const unsigned char *data, size_t len);
static int govfuzz_run_harness(const char *harness_path,
                               char *const child_argv[],
                               const unsigned char *data,
                               size_t len);

#ifndef __AFL_INIT
#define __AFL_INIT() ((void)0)
#endif

#ifndef __AFL_LOOP
static int govfuzz_afl_fallback_loop_remaining = 1;
#define __AFL_LOOP(_max) (govfuzz_afl_fallback_loop_remaining-- > 0)
#endif

#ifndef __AFL_FUZZ_TESTCASE_BUF
static unsigned char govfuzz_afl_fallback_buf[GOVFUZZ_AFL_FALLBACK_MAX_INPUT];
#define __AFL_FUZZ_TESTCASE_BUF govfuzz_afl_fallback_buf
#endif

#ifndef __AFL_FUZZ_TESTCASE_LEN
#define __AFL_FUZZ_TESTCASE_LEN                                                \
   govfuzz_read_stdin(__AFL_FUZZ_TESTCASE_BUF, GOVFUZZ_AFL_FALLBACK_MAX_INPUT)
#endif

#ifndef __AFL_FUZZ_INIT
#define __AFL_FUZZ_INIT() /* AFL++ defines this when instrumented. */
#endif

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
   const char *harness_path;
   char **child_argv;
   unsigned char *buf;

   if (argc < 2) {
      fprintf(stderr, "usage: %s <harness-binary> [harness-args...]\n", argv[0]);
      return 2;
   }

   harness_path = argv[1];
   child_argv = &argv[1];

#ifdef __AFL_HAVE_MANUAL_CONTROL
   __AFL_INIT();
#endif

   buf = __AFL_FUZZ_TESTCASE_BUF;
   while (__AFL_LOOP(10000)) {
      size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
      int status = govfuzz_run_harness(harness_path, child_argv, buf, len);
      if (status != 0) {
         return status;
      }
   }

   return 0;
}

static size_t govfuzz_read_stdin(unsigned char *buf, size_t capacity) {
   size_t total = 0;

   while (total < capacity) {
      ssize_t count = read(STDIN_FILENO, buf + total, capacity - total);
      if (count == 0) {
         break;
      }
      if (count < 0) {
         if (errno == EINTR) {
            continue;
         }
         break;
      }
      total += (size_t)count;
   }

   return total;
}

static int govfuzz_write_all(int fd, const unsigned char *data, size_t len) {
   size_t written = 0;

   while (written < len) {
      ssize_t count = write(fd, data + written, len - written);
      if (count < 0) {
         if (errno == EINTR) {
            continue;
         }
         if (errno == EPIPE) {
            return 0;
         }
         return -1;
      }
      written += (size_t)count;
   }

   return 0;
}

static int govfuzz_run_harness(const char *harness_path,
                               char *const child_argv[],
                               const unsigned char *data,
                               size_t len) {
   int pipefd[2];
   pid_t pid;
   int status = 0;
   int write_status;

   if (pipe(pipefd) != 0) {
      return 2;
   }

   pid = fork();
   if (pid < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      return 2;
   }

   if (pid == 0) {
      close(pipefd[1]);
      if (dup2(pipefd[0], STDIN_FILENO) < 0) {
         _exit(126);
      }
      close(pipefd[0]);
      execv(harness_path, child_argv);
      _exit(127);
   }

   close(pipefd[0]);
   write_status = govfuzz_write_all(pipefd[1], data, len);
   close(pipefd[1]);

   while (waitpid(pid, &status, 0) < 0) {
      if (errno != EINTR) {
         return 2;
      }
   }

   if (write_status != 0) {
      return 2;
   }
   if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);
      signal(sig, SIG_DFL);
      raise(sig);
      _exit(128 + sig);
   }
   if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
   }

   return 1;
}
