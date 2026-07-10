// SPDX-License-Identifier: Apache-2.0
// Uses an undeclared type `widget_t` so auto synthesizes a typedef
// placeholder. The expected result is the `synthesized_types`
// bucket lists `widget_t`.
//
// `widget_t` MUST appear in a type-context (parameter list, file-scope
// variable, typedef) for clang to emit "unknown type name 'widget_t'"
// — value-context usage gives "use of undeclared identifier" which the
// classifier doesn't recognise.

extern widget_t widget_global;

int widget_parse(const unsigned char *d, unsigned long n) {
    (void)d;
    (void)widget_global;
    return (int)n;
}
