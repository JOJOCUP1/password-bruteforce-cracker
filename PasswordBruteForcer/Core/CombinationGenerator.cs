namespace PasswordBruteForcer.Core;

public sealed class CombinationGenerator
{
    private readonly char[] _charset;

    public CombinationGenerator(char[] charset)
    {
        if (charset is null || charset.Length == 0)
            throw new ArgumentException("Character set must not be empty.", nameof(charset));
        _charset = charset;
    }

    public char[] Charset => _charset;
    public int CharsetSize => _charset.Length;

    public long CombinationCount(int length)
    {
        long count = 1;
        for (int i = 0; i < length; i++)
            count *= _charset.Length;
        return count;
    }

    public Cursor Enumerate(int firstCharIndex, int length) => new(_charset, firstCharIndex, length);

    public IEnumerable<string> GenerateWithFirstChar(int firstCharIndex, int length)
    {
        Cursor cursor = Enumerate(firstCharIndex, length);
        while (cursor.MoveNext())
            yield return new string(cursor.Current);
    }

    public IEnumerable<string> Generate(int length)
    {
        for (int first = 0; first < _charset.Length; first++)
            foreach (string candidate in GenerateWithFirstChar(first, length))
                yield return candidate;
    }

    public struct Cursor
    {
        private readonly char[] _charset;
        private readonly char[] _buffer;
        private readonly int[] _indices;
        private readonly int _length;
        private readonly int _rest;
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

        public readonly ReadOnlySpan<char> Current => _buffer.AsSpan(0, _length);

        public bool MoveNext()
        {
            if (_done) return false;

            if (!_started)
            {
                _started = true;
                WriteTrailingPositions();
                return true;
            }

            if (_rest == 0)
            {
                _done = true;
                return false;
            }

            int n = _charset.Length;
            int pos = _rest - 1;
            while (pos >= 0)
            {
                if (++_indices[pos] < n) break;
                _indices[pos] = 0;
                pos--;
            }

            if (pos < 0)
            {
                _done = true;
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
