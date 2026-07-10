/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Force-fuzz Phase 2 negative fixture: a translation unit that cannot be built
 * even with the aggressive diagnostic-driven stubbing that `--force` enables.
 *
 * `parse_widget` takes an int (so it is a fuzzable, discoverable candidate) but
 * its body references an undefined external type `widget_state_t` BY VALUE and
 * then dereferences a member on it (`.tag`). Force will synthesize an opaque
 * placeholder for `widget_state_t` (`typedef struct { unsigned char _b[N]; }
 * widget_state_t;`), but member access on that opaque byte-array placeholder is
 * a hard semantic error ("no member named 'tag'") that no further repair can
 * resolve. A blind symbol stub cannot help because the failure is a type/member
 * error in the harnessed function's own body, not an undefined link symbol.
 *
 * WITHOUT --force: the pre-build gate / repair loop cannot resolve the external
 * type, so the target is a failed_build.
 * WITH --force: stubbing is attempted every round, still fails, and the terminal
 * force floor degrades the outcome to report-only (a static scan) — never a bare
 * failed_build.
 */

extern int lookup_tag(int);

int parse_widget(int seed) {
    widget_state_t st = make_widget_state(seed);
    return lookup_tag(st.tag) + st.count;
}
