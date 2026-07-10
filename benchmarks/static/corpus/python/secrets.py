# SPDX-License-Identifier: Apache-2.0
# GF-429 committed-secret detection: recognized provider formats are flagged;
# documentation placeholders and too-short lookalikes are not.
AWS_KEY = "AKIA1234567890ABCDEF"                          # EXPECT GF-429
GH_TOKEN = "ghp_0123456789abcdef0123456789abcdefABCD"     # EXPECT GF-429
GOOGLE = "AIzaSyA0123456789abcdefghijklmnopqrstuvz"       # EXPECT GF-429
EXAMPLE = "AKIAIOSFODNN7EXAMPLE"                          # safe: AWS doc placeholder
SHORT = "AKIAshort"                                       # safe: too short to be a key
