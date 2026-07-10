<!-- SPDX-License-Identifier: Apache-2.0 -->

# Access Parameter

M8 fixture for an access-typed formal parameter. The generated harness owns a
per-parameter slot table and decodes either null or a table slot for
`Access_Param.Process`.

M8 intentionally initializes all slots to null. That proves the harness shape
compiles, but it cannot reach the swallowed `Constraint_Error` branch yet. M9
adds constructor-driven slot population for non-null access values.
