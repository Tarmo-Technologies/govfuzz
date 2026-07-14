# SPDX-License-Identifier: Apache-2.0
# A tiny Ruby parser fixture for the M3.9 native Ruby lane end-to-end test. The
# `RecordParser.parse_record` method divides by the number of digits in the input
# without guarding the zero case — a planted ZeroDivisionError (CWE-369) that fires
# on any digit-free input, which the lane should surface quickly.
module RecordParser
  def self.parse_record(text)
    digits = text.scan(/[0-9]/).length
    1000 / digits
  end
end
