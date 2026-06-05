using System.Security.Cryptography;
using System.Text;

namespace PasswordBruteForcer.Core;

public sealed class PasswordHasher
{
    public const string Salt = "P@ssCkr::Static$alt::2026";
    private static readonly byte[] SaltBytes = Encoding.UTF8.GetBytes(Salt);
    private static readonly int SaltLength = SaltBytes.Length;
    public const int HashByteLength = 32;

    public string Hash(string password)
    {
        Span<byte> digest = stackalloc byte[HashByteLength];
        ComputeHash(password.AsSpan(), digest);
        return Convert.ToHexString(digest);
    }

    public void ComputeHash(string password, Span<byte> destination)
        => ComputeHash(password.AsSpan(), destination);

    public void ComputeHash(ReadOnlySpan<char> password, Span<byte> destination)
    {
        int passByteCount = Encoding.UTF8.GetByteCount(password);
        int total = SaltLength + passByteCount;
        byte[]? rented = null;
        Span<byte> buffer = total <= 128 ? stackalloc byte[128] : (rented = new byte[total]);
        SaltBytes.CopyTo(buffer);
        Encoding.UTF8.GetBytes(password, buffer.Slice(SaltLength));
        SHA256.HashData(buffer.Slice(0, total), destination);
        _ = rented;
    }
}
