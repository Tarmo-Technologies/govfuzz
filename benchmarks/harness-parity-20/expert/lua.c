/* SPDX-License-Identifier: Apache-2.0 */
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  lua_State *state = luaL_newstate();
  if (!state) return 0;
  (void)luaL_loadbufferx(state, (const char *)data, size, "fuzz", NULL);
  lua_close(state);
  return 0;
}
