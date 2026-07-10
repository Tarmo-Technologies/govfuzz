// SPDX-License-Identifier: Apache-2.0
// A pimpl idiom: EncryptionParametersImpl is forward-declared here but defined
// only in crypto.cpp, so a harness that includes this header sees an INCOMPLETE
// type. A function returning it by value fails to compile in the harness TU
// ("incomplete return type"). govfuzz must classify this as IncompleteType and
// degrade the target to report-only, not a hard failed-build.
class EncryptionParametersImpl;
EncryptionParametersImpl load_params(const char *data, unsigned long len);
