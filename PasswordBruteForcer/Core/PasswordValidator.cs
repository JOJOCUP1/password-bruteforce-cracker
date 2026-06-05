namespace PasswordBruteForcer.Core;

/// <summary>
/// Task 7 — The brute-force VALIDATOR, implemented separately and independently of the
/// <see cref="CombinationGenerator"/>. The generator produces candidates; this class decides
/// whether a candidate is the password by hashing it (with the shared <see cref="PasswordHasher"/>)
/// and comparing the digest to the target hash.
///
/// It holds the target as raw bytes and compares digests byte-by-byte, so the hot brute-force
/// loop performs no per-candidate string allocations. It is stateless after construction and
/// therefore safe to share across all worker threads.
/// </summary>
public sealed class PasswordValidator
{
    private readonly PasswordHasher _hasher;
    private readonly byte[] _targetHash; // 32 raw bytes of the SHA-256 target digest

    /// <param name="targetHashHex">Hex string of the target SHA-256 hash (case-insensitive).</param>
    /// <param name="hasher">Shared hasher that knows the constant salt.</param>
    public PasswordValidator(string targetHashHex, PasswordHasher hasher)
    {
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
        _targetHash = Convert.FromHexString(targetHashHex);
        if (_targetHash.Length != PasswordHasher.HashByteLength)
            throw new ArgumentException("Target hash is not a valid SHA-256 digest.", nameof(targetHashHex));
    }

    /// <summary>
    /// Returns <c>true</c> when <paramref name="candidate"/> hashes to the target digest.
    /// Allocation-free: the digest is computed into a stack buffer and compared in place. This
    /// span overload lets the engine validate the generator's reused buffer without allocating.
    /// </summary>
    public bool IsMatch(ReadOnlySpan<char> candidate)
    {
        Span<byte> digest = stackalloc byte[PasswordHasher.HashByteLength];
        _hasher.ComputeHash(candidate, digest);
        return digest.SequenceEqual(_targetHash);
    }

    /// <summary>Convenience string overload of <see cref="IsMatch(ReadOnlySpan{char})"/>.</summary>
    public bool IsMatch(string candidate) => IsMatch(candidate.AsSpan());
}
