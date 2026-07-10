// SPDX-License-Identifier: Apache-2.0
//
// govfuzz fuzz target for miniz. Auto discovers `miniz_inflate_fuzz`
// via its (const unsigned char*, unsigned long) signature.
//
// Calls into miniz AND a handful of runtime resources whose Layer-C
// buckets the build-recovery scenarios assert against:
//
//   - getenv("MINIZ_TEMP_DIR")        -> environment_variables_faked
//   - open("/etc/miniz_govfuzz_config.conf") -> missing_files
//   - dlopen("libgovfuzz_vendor...")  -> dlopen_failures
//   - connect("/tmp/govfuzz_missing.sock") -> network_endpoints
//
// Every call site is unconditional so a single fuzz input triggers
// every Layer-C event; the runtrace_shim hooks observe them via the
// LD_PRELOAD'd shim auto loads for us.

#include "miniz.h"
#include "vendor/vendor.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int miniz_inflate_fuzz(const unsigned char *data, unsigned long len) {
    if (len > (1u << 20)) {
        return 0;
    }

    // env_var scenario locator.
    (void)getenv("MINIZ_TEMP_DIR");

    // missing_files scenario locator. Unique-looking path so a
    // pre-existing /etc/miniz.conf on the host can't make this
    // accidentally exist.
    int fd = open("/etc/miniz_govfuzz_config.conf", O_RDONLY);
    if (fd >= 0) {
        close(fd);
    }

    // dlopen_failures scenario locator. The library doesn't exist
    // so dlopen returns NULL on every iteration.
    void *h = dlopen("libgovfuzz_vendor_does_not_exist.so.42", RTLD_NOW);
    if (h) {
        dlclose(h);
    }

    // network_endpoints scenario locator. A missing Unix-domain
    // socket fails immediately with ENOENT and is audited by the
    // runtrace shim's endpoint policy.
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/tmp/govfuzz_missing.sock", sizeof(addr.sun_path) - 1);
        (void)connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }

    // Vendor-subdir scenario locator. Calls a symbol whose
    // declaration lives in vendor/vendor.h.
    (void)vendor_helper((unsigned long)len);

    if (len < 2) {
        return 0;
    }
    unsigned char out[4096];
    mz_ulong out_len = sizeof(out);
    (void)mz_uncompress(out, &out_len, data, (mz_ulong)len);
    return 0;
}
