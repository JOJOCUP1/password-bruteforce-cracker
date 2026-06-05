namespace PasswordBruteForcer.Core;

/// <summary>
/// Task 4b — Generates the secret target password whose length is randomly chosen in the
/// half-open interval [4, 6); that is, the length is either 4 or 5 characters.
///
/// The generator draws characters from the SAME character set the brute-force engine searches,
/// otherwise the password could never be found. It is intentionally tiny and independent of
/// hashing and brute forcing.
/// </summary>
public sealed class PasswordGenerator
{
    /// <summary>Inclusive lower bound of the password length (4).</summary>
    public const int MinLength = 4;

    /// <summary>Exclusive upper bound of the password length (6) — so lengths are 4 or 5.</summary>
    public const int MaxLengthExclusive = 6;

    private readonly char[] _charset;
    private readonly Random _random;

    /// <param name="charset">Alphabet the password is built from (same set the cracker uses).</param>
    public PasswordGenerator(char[] charset)
    {
        if (charset is null || charset.Length == 0)
            throw new ArgumentException("Character set must not be empty.", nameof(charset));
        _charset = charset;
        _random = new Random();
    }

    /// <summary>
    /// Returns a fresh random password of length 4 or 5, using characters from the configured set.
    /// </summary>
    public string Generate()
    {
        // Random.Next(min, maxExclusive) => [MinLength, MaxLengthExclusive) => 4 or 5.
        int length = _random.Next(MinLength, MaxLengthExclusive);

        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = _charset[_random.Next(_charset.Length)];

        return new string(chars);
    }
}
