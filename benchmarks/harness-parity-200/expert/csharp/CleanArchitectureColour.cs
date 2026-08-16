// SPDX-License-Identifier: Apache-2.0

using CleanArchitecture.Domain.Exceptions;
using CleanArchitecture.Domain.ValueObjects;
using SharpFuzz;

public static class ExpertColourHarness
{
    public static void Main() => Fuzzer.OutOfProcess.Run(stream =>
    {
        using var reader = new StreamReader(stream);
        try
        {
            _ = Colour.From(reader.ReadToEnd());
        }
        catch (UnsupportedColourException)
        {
            // Documented input rejection, not a finding.
        }
    });
}
