namespace PasswordBruteForcer.Core;

public sealed class PasswordGenerator
{
    public const int MinLength = 4;
    public const int MaxLengthExclusive = 6;
    private readonly char[] _charset;
    private readonly Random _random;

    public PasswordGenerator(char[] charset)
    {
        if (charset is null || charset.Length == 0)
            throw new ArgumentException("Character set must not be empty.", nameof(charset));
        _charset = charset;
        _random = new Random();
    }

    public string Generate()
    {
        int length = _random.Next(MinLength, MaxLengthExclusive);
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = _charset[_random.Next(_charset.Length)];
        return new string(chars);
    }
}
