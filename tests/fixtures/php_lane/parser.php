<?php
// SPDX-License-Identifier: Apache-2.0
// A tiny PHP parser fixture for the M3.11 native PHP lane end-to-end test. The
// `parse_record` static method divides by the digit count without guarding zero — a
// planted DivisionByZeroError (PHP 8) that fires on any digit-free input.
namespace Demo;
class Parser {
    public static function parse_record(string $text): int {
        $digits = preg_match_all('/[0-9]/', $text);
        return intdiv(1000, $digits);
    }
}
