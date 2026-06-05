using System.Security.Cryptography;
using System.Text;

namespace PasswordBruteForcer.Core;

/// <summary>
/// Task 4a — Hashes passwords with SHA-256 using a single constant ("static") salt
/// that is baked into the application. The same salt is concatenated in front of every
/// password before hashing, exactly like the references in the assignment brief.
///
/// This class is completely independent of password generation and brute forcing:
/// it only knows how to turn a plain-text string into a salted SHA-256 hash.
/// </summary>
public sealed class PasswordHasher
{
    /// <summary>
    /// The constant, application-wide salt. It never changes between runs, so the same
    /// password always produces the same hash (a requirement for the brute-force search
    /// to be able to reproduce and match the target hash).
    /// </summary>
    public const string Salt = "P@ssCkr::Static$alt::2026";

    private static readonly byte[] SaltBytes = Encoding.UTF8.GetBytes(Salt);
    private static readonly int SaltLength = SaltBytes.Length;

    /// <summary>Number of bytes a SHA-256 digest occupies (256 bits / 8).</summary>
    public const int HashByteLength = 32;

    /// <summary>
    /// Computes the salted SHA-256 digest of <paramref name="password"/> and returns it
    /// as an uppercase hexadecimal string (used for display and for storing the target hash).
    /// </summary>
    public string Hash(string password)
    {
        Span<byte> digest = stackalloc byte[HashByteLength];
        ComputeHash(password, digest);
        return Convert.ToHexString(digest); // uppercase hex, e.g. "A1B2..."
    }

    /// <summary>
    /// Hot-path hashing used by the validator during brute forcing. Writes the 32-byte
    /// SHA-256 digest of (salt + password) into <paramref name="destination"/> without
    /// allocating a string. <see cref="SHA256.HashData(ReadOnlySpan{byte}, Span{byte})"/>
    /// is a stateless static method, so this is safe to call from many threads at once.
    /// </summary>
    /// <param name="password">Plain-text candidate (in this app always 1–6 ASCII chars).</param>
    /// <param name="destination">A span of at least 32 bytes that receives the digest.</param>
    public void ComputeHash(string password, Span<byte> destination)
        => ComputeHash(password.AsSpan(), destination);

    /// <summary>
    /// Span-based overload of <see cref="ComputeHash(string, Span{byte})"/>. The brute-force engine
    /// calls this with the generator's reused character buffer, so a candidate can be hashed without
    /// ever being turned into a <see cref="string"/> — that keeps the multi-threaded hot loop free
    /// of per-candidate allocations (and therefore free of GC contention across the worker threads).
    /// </summary>
    public void ComputeHash(ReadOnlySpan<char> password, Span<byte> destination)
    {
        int passByteCount = Encoding.UTF8.GetByteCount(password);
        int total = SaltLength + passByteCount;

        // Fast path: keep the (salt + password) buffer on the stack for short inputs.
        // Falls back to the heap only for unusually long passwords so the method stays correct.
        byte[]? rented = null;
        Span<byte> buffer = total <= 128 ? stackalloc byte[128] : (rented = new byte[total]);

        SaltBytes.CopyTo(buffer);
        Encoding.UTF8.GetBytes(password, buffer.Slice(SaltLength));
        SHA256.HashData(buffer.Slice(0, total), destination);

        _ = rented; // buffer is reclaimed by the GC; reference kept alive until here
    }
}
