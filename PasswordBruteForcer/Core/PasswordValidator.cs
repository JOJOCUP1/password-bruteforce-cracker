namespace PasswordBruteForcer.Core;

public sealed class PasswordValidator
{
    private readonly PasswordHasher _hasher;
    private readonly byte[] _targetHash;

    public PasswordValidator(string targetHashHex, PasswordHasher hasher)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
        _targetHash = Convert.FromHexString(targetHashHex);
        if (_targetHash.Length != PasswordHasher.HashByteLength)
            throw new ArgumentException("Invalid SHA-256 hash.", nameof(targetHashHex));
    }

    public bool IsMatch(ReadOnlySpan<char> candidate)
    {
        Span<byte> digest = stackalloc byte[PasswordHasher.HashByteLength];
        _hasher.ComputeHash(candidate, digest);
        return digest.SequenceEqual(_targetHash);
    }

    public bool IsMatch(string candidate) => IsMatch(candidate.AsSpan());
}
