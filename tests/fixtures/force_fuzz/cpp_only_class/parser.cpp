// SPDX-License-Identifier: Apache-2.0
#include "parser.hpp"

// Parser is declared and defined only in this translation unit; it appears in no
// header. An external harness #includes parser.hpp (which does not declare it),
// so Parser is an undefined type there — the ".cpp-only class" pre-build gate
// pre-skips Parser::scan as unsupported_params UNLESS --force bypasses the gate.
class Parser {
public:
    int scan(const unsigned char *d, unsigned long n) {
        if (n > 2 && d[0] == 'O' && d[1] == 'K') {
            return 1;
        }
        return 0;
    }
};

int gf_parser_version(void) { return 1; }
