#include <msgpack.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  msgpack_unpacked result;
  msgpack_unpacked_init(&result);
  size_t offset = 0;
  while (offset < size) {
    size_t before = offset;
    msgpack_unpack_return status = msgpack_unpack_next(
        &result, (const char *)data, size, &offset);
    if (status == MSGPACK_UNPACK_CONTINUE || status < 0 || offset <= before) break;
  }
  msgpack_unpacked_destroy(&result);
  return 0;
}
