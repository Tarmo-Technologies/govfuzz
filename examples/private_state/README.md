<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private State

This fixture exercises M9 stateful sequence harnessing. `State.Pop` only underflows after earlier calls mutate package-private state, so a direct single-call harness is not enough to demonstrate the swallowed `Constraint_Error`.
