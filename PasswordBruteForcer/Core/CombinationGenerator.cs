namespace PasswordBruteForcer.Core;

/// <summary>
/// Task 4c &amp; Task 7 — The brute-force candidate GENERATOR.
///
/// It produces every possible combination of the character set for a requested length. It is
/// implemented completely independently of the validator/hasher (Task 7): it knows nothing about
/// the target hash and never decides whether a candidate is correct — it only enumerates strings.
///
/// Two ways to consume it:
///   • <see cref="Generate"/> / <see cref="GenerateWithFirstChar"/> return readable IEnumerable&lt;string&gt;.
///   • <see cref="Enumerate"/> returns an allocation-free <see cref="Cursor"/> that writes each
///     candidate into a reused buffer — this is what the engine uses in its hot loop so that
///     hashing millions of candidates across 11 threads does not drown the GC in tiny strings.
///
/// To support multi-threading, the keyspace of a given length is partitioned by the FIRST
/// character, so each worker thread can sweep a disjoint slice of the combinations independently.
/// </summary>
public sealed class CombinationGenerator
{
    private readonly char[] _charset;

    /// <param name="charset">Alphabet to build combinations from (e.g. 'a'..'z').</param>
    public CombinationGenerator(char[] charset)
    {
        if (charset is null || charset.Length == 0)
            throw new ArgumentException("Character set must not be empty.", nameof(charset));
        _charset = charset;
    }

    /// <summary>The alphabet this generator enumerates.</summary>
    public char[] Charset => _charset;

    /// <summary>Number of symbols in the alphabet.</summary>
    public int CharsetSize => _charset.Length;

    /// <summary>
    /// Total number of combinations of EXACTLY the given length: charsetSize ^ length.
    /// Used by the UI to show how far through the current length the search has progressed.
    /// </summary>
    public long CombinationCount(int length)
    {
        long count = 1;
        for (int i = 0; i < length; i++)
            count *= _charset.Length;
        return count;
    }

    /// <summary>
    /// Allocation-free enumeration of every combination of the requested length whose FIRST
    /// character is <c>Charset[firstCharIndex]</c>. Each call returns a fresh <see cref="Cursor"/>
    /// that fills its own reused buffer; <see cref="Cursor.Current"/> is valid after every
    /// successful <see cref="Cursor.MoveNext"/>. This is the unit of work given to a worker thread.
    /// </summary>
    public Cursor Enumerate(int firstCharIndex, int length) => new(_charset, firstCharIndex, length);

    /// <summary>
    /// Readable equivalent of <see cref="Enumerate"/> that yields strings. Handy for tests and for
    /// understanding the generator; the engine itself uses the allocation-free cursor.
    /// </summary>
    public IEnumerable<string> GenerateWithFirstChar(int firstCharIndex, int length)
    {
        Cursor cursor = Enumerate(firstCharIndex, length);
        while (cursor.MoveNext())
            yield return new string(cursor.Current);
    }

    /// <summary>Readable enumeration of EVERY combination of the requested length (all first chars).</summary>
    public IEnumerable<string> Generate(int length)
    {
        for (int first = 0; first < _charset.Length; first++)
            foreach (string candidate in GenerateWithFirstChar(first, length))
                yield return candidate;
    }

    /// <summary>
    /// A forward-only cursor over the combinations of a fixed length that share a fixed first
    /// character. It works like a mechanical odometer: the trailing positions count up through the
    /// alphabet, carrying to the left on overflow. The current candidate is exposed as a
    /// <see cref="ReadOnlySpan{T}"/> over an internal buffer, so iterating allocates nothing.
    /// </summary>
    public struct Cursor
    {
        private readonly char[] _charset;
        private readonly char[] _buffer;   // holds the current candidate; length == _length
        private readonly int[] _indices;   // odometer wheels for positions 1.._length-1
        private readonly int _length;
        private readonly int _rest;        // number of trailing (variable) positions
        private bool _started;
        private bool _done;

        internal Cursor(char[] charset, int firstCharIndex, int length)
        {
            _charset = charset;
            _length = length;
            _rest = Math.Max(0, length - 1);
            _buffer = new char[Math.Max(length, 1)];
            _indices = _rest > 0 ? new int[_rest] : Array.Empty<int>();
            if (length > 0)
                _buffer[0] = charset[firstCharIndex];
            _started = false;
            _done = length <= 0;
        }

        /// <summary>The current candidate. Valid only after <see cref="MoveNext"/> returned true.</summary>
        public readonly ReadOnlySpan<char> Current => _buffer.AsSpan(0, _length);

        /// <summary>Advances to the next candidate; returns false when the block is exhausted.</summary>
        public bool MoveNext()
        {
            if (_done)
                return false;

            if (!_started)
            {
                _started = true;
                WriteTrailingPositions();   // first candidate: all trailing wheels at 0
                return true;
            }

            if (_rest == 0)
            {
                _done = true;               // length-1 block has exactly one combination
                return false;
            }

            // Advance the odometer: increment the right-most wheel, carry left on overflow.
            int n = _charset.Length;
            int pos = _rest - 1;
            while (pos >= 0)
            {
                if (++_indices[pos] < n)
                    break;
                _indices[pos] = 0;
                pos--;
            }

            if (pos < 0)
            {
                _done = true;               // every wheel rolled over => block complete
                return false;
            }

            WriteTrailingPositions();
            return true;
        }

        private readonly void WriteTrailingPositions()
        {
            for (int p = 0; p < _rest; p++)
                _buffer[p + 1] = _charset[_indices[p]];
        }
    }
}
