using System.Buffers.Binary;
using System.Text;

namespace AceMetaUnpack;

internal sealed class Processor
{
	private readonly byte[] _metaData;

	private Il2CppGlobalMetadataHeader _header;
	private Il2CppStringLiteral[] _stringLiterals = Array.Empty<Il2CppStringLiteral>();

	private bool _initialized;
	private bool _stringLiteralsPatched;

	private const int StringLiteralInfoOffsetField = 8;
	private const int StringLiteralCountField = 12;
	private const int StringLiteralDataOffsetField = 16;
	private const int StringLiteralEntrySizeBytes = 8;
	private const int StringOffset = 24;
	private const int StringOffset2 = 32;

	public Processor(byte[] metadata)
	{
		_metaData = metadata ?? throw new ArgumentNullException(nameof(metadata));
		if (_metaData.Length < 20)
			throw new ArgumentException("Metadata buffer is too small to contain the required header fields.", nameof(metadata));
	}

	public void Initialize()
	{
		_header = ReadHeaderMinimal();
		_stringLiterals = ReadStringLiteralTable(_header);
		_initialized = true;
	}

	public void EnsureStringLiteralsPatchedIfNeeded(Encoding? encoding = null, int probeCount = 256)
	{
		EnsureInitialized();

		if (_stringLiteralsPatched)
			return;

		encoding ??= Encoding.UTF8;

		bool foundUnity = ContainsUnityLiteralPrefix(encoding, probeCount);

		if (!foundUnity)
		{
			PatchStringLiteralsInPlace();
			_stringLiteralsPatched = true;
		}
	}

	public void DecryptMetadataStrings()
	{
		EnsureInitialized();

		if (_metaData.Length < StringOffset + 8)
			throw new InvalidOperationException("Metadata buffer is too small to contain Blowfish key fields.");

		uint offset = ReadUInt32LE(_metaData, StringOffset);
		uint size = ReadUInt32LE(_metaData, StringOffset + 4);

		if (offset > _metaData.Length || size > _metaData.Length - offset)
			throw new InvalidOperationException(
				$"Encrypted metadata string range is out of bounds. offset=0x{offset:X}, size=0x{size:X}, buffer=0x{_metaData.Length:X}");

		byte[] key =
		{
		_metaData[StringOffset + 0],
		_metaData[StringOffset + 1],
		_metaData[StringOffset + 2],
		_metaData[StringOffset + 3],
		_metaData[StringOffset + 4],
		_metaData[StringOffset + 5],
		_metaData[StringOffset + 6],
		_metaData[StringOffset + 7],
	};

		var blowfish = new Blowfish(key);

		int blockCount = checked((int)(size / 8));
		int baseOffset = checked((int)offset);

		for (int i = 0; i < blockCount; i++)
		{
			int blockOffset = baseOffset + (i * 8);

			uint left = ReadUInt32LE(_metaData, blockOffset);
			uint right = ReadUInt32LE(_metaData, blockOffset + 4);

			blowfish.Decrypt(ref left, ref right);

			BinaryPrimitives.WriteUInt32LittleEndian(_metaData.AsSpan(blockOffset, 4), left);
			BinaryPrimitives.WriteUInt32LittleEndian(_metaData.AsSpan(blockOffset + 4, 4), right);
		}
	}

	public void PatchStringLiteralsInPlace()
	{
		EnsureInitialized();

		for (uint i = 0; i < (uint)_stringLiterals.Length; i++)
		{
			var lit = _stringLiterals[i];
			if (lit.length == 0)
				continue;

			if (!TryGetLiteralRange(lit, out int pos, out int len, out string? reason))
			{
				Console.Error.WriteLine($"[WARN] Skipping string literal {i}: {reason}");
				continue;
			}

			byte xorKey = unchecked((byte)(lit.length ^ 0x2E));
			for (int j = 0; j < len; j++)
				_metaData[pos + j] ^= xorKey;
		}
	}

	public string GetStringLiteralFromIndex(uint index, Encoding? encoding = null)
	{
		EnsureInitialized();
		encoding ??= Encoding.UTF8;

		if (index >= (uint)_stringLiterals.Length)
			throw new ArgumentOutOfRangeException(nameof(index));

		var lit = _stringLiterals[index];

		if (lit.length == 0)
			return string.Empty;

		if (!TryGetLiteralRange(lit, out int pos, out int len, out string? reason))
			throw new InvalidOperationException($"String literal {index} is invalid: {reason}");

		var bytes = new byte[len];
		Buffer.BlockCopy(_metaData, pos, bytes, 0, len);

		if (!_stringLiteralsPatched)
		{
			byte xorKey = unchecked((byte)(lit.length ^ 0x2E));
			for (int i = 0; i < len; i++)
				bytes[i] ^= xorKey;
		}

		int trimmedLen = TrimTrailingNullsLength(bytes);
		return encoding.GetString(bytes, 0, trimmedLen);
	}

	public void PrintAllStringLiterals(Encoding? encoding = null)
	{
		EnsureInitialized();
		encoding ??= Encoding.UTF8;

		for (uint i = 0; i < (uint)_stringLiterals.Length; i++)
		{
			string value;
			try
			{
				value = GetStringLiteralFromIndex(i, encoding);
			}
			catch (Exception ex)
			{
				value = $"<error: {ex.Message}>";
			}

			Console.WriteLine($"[{i:D6}] {value}");
		}
	}

	private void EnsureInitialized()
	{
		if (!_initialized)
			throw new InvalidOperationException("Processor is not initialized. Call Initialize() first.");
	}

	private Il2CppGlobalMetadataHeader ReadHeaderMinimal()
	{
		int stringLiteralOffset = ReadInt32LE(_metaData, StringLiteralInfoOffsetField);
		int stringLiteralSize = ReadInt32LE(_metaData, StringLiteralCountField);
		int stringLiteralDataOffset = ReadInt32LE(_metaData, StringLiteralDataOffsetField);
		int stringOffset = ReadInt32LE(_metaData, StringOffset);
		int stringSize = ReadInt32LE(_metaData, StringOffset2);

		return new Il2CppGlobalMetadataHeader(
			stringLiteralOffset: stringLiteralOffset,
			stringLiteralSize: stringLiteralSize,
			stringLiteralDataOffset: stringLiteralDataOffset,
			StringOffset: stringOffset,
			StringSize: stringSize
		);
	}

	private Il2CppStringLiteral[] ReadStringLiteralTable(Il2CppGlobalMetadataHeader header)
	{
		if (header.stringLiteralSize == 0)
			return Array.Empty<Il2CppStringLiteral>();

		if (header.stringLiteralSize % StringLiteralEntrySizeBytes != 0)
			throw new InvalidOperationException(
				$"stringLiteralSize is not a multiple of {StringLiteralEntrySizeBytes} (size={header.stringLiteralSize}).");

		if (header.stringLiteralOffset > (uint)_metaData.Length ||
			header.stringLiteralSize > (uint)_metaData.Length - header.stringLiteralOffset)
		{
			throw new InvalidOperationException("String literal table is out of bounds.");
		}

		int count = checked((int)(header.stringLiteralSize / StringLiteralEntrySizeBytes));
		var result = new Il2CppStringLiteral[count];

		int baseOffset = checked((int)header.stringLiteralOffset);
		for (int i = 0; i < count; i++)
		{
			int entryOffset = baseOffset + (i * StringLiteralEntrySizeBytes);

			uint length = ReadUInt32LE(_metaData, entryOffset);
			uint dataIndex = ReadUInt32LE(_metaData, entryOffset + 4);

			result[i] = new Il2CppStringLiteral(length, dataIndex);
		}

		return result;
	}

	private static bool LiteralIsHeuristicSafe(Il2CppStringLiteral lit)
	{
		if (lit.length == 0x2E)
			return false;

		if (lit.length < 5)
			return false;

		if (lit.length > 1_000_000)
			return false;

		return true;
	}

	private bool ContainsUnityLiteralPrefix(Encoding encoding, int probeCount)
	{
		uint total = (uint)_stringLiterals.Length;
		if (total == 0)
			return false;

		int n = Math.Clamp(probeCount, 1, (int)total);

		for (uint i = 0; i < (uint)n; i++)
		{
			if (LiteralIsHeuristicSafe(_stringLiterals[i]) && LooksLikeUnity(TryGetLiteralAsIfUnpatched(i, encoding)))
				return true;
		}

		uint mid = total / 2;
		for (uint i = 0; i < 16 && mid + i < total; i++)
		{
			var lit = _stringLiterals[mid + i];
			if (LiteralIsHeuristicSafe(lit) && LooksLikeUnity(TryGetLiteralAsIfUnpatched(mid + i, encoding)))
				return true;
		}

		uint startTail = total > 32 ? total - 32 : 0;
		for (uint i = startTail; i < total; i++)
		{
			if (LiteralIsHeuristicSafe(_stringLiterals[i]) && LooksLikeUnity(TryGetLiteralAsIfUnpatched(i, encoding)))
				return true;
		}

		return false;
	}

	private string TryGetLiteralPlainText(uint index, Encoding encoding)
	{
		if (index >= (uint)_stringLiterals.Length)
			return string.Empty;

		var lit = _stringLiterals[index];
		if (lit.length == 0)
			return string.Empty;

		if (!TryGetLiteralRange(lit, out int pos, out int len, out _))
			return string.Empty;

		var bytes = new byte[len];
		Buffer.BlockCopy(_metaData, pos, bytes, 0, len);

		byte xorKey = unchecked((byte)(lit.length ^ 0x2E));
		for (int i = 0; i < len; i++)
			bytes[i] ^= xorKey;

		int trimmedLen = TrimTrailingNullsLength(bytes);

		Encoding safe = (Encoding)encoding.Clone();
		safe.DecoderFallback = DecoderFallback.ReplacementFallback;
		safe.EncoderFallback = EncoderFallback.ReplacementFallback;

		return safe.GetString(bytes, 0, trimmedLen);
	}

	private string TryGetLiteralAsIfUnpatched(uint index, Encoding encoding)
	{
		if (index >= (uint)_stringLiterals.Length)
			return string.Empty;

		var lit = _stringLiterals[index];
		if (lit.length == 0)
			return string.Empty;

		if (!TryGetLiteralRange(lit, out int pos, out int len, out _))
			return string.Empty;

		var bytes = new byte[len];
		Buffer.BlockCopy(_metaData, pos, bytes, 0, len);

		byte xorKey = unchecked((byte)(lit.length ^ 0x2E));
		if (xorKey != 0)
		{
			for (int i = 0; i < len; i++)
				bytes[i] ^= xorKey;
		}

		int trimmedLen = TrimTrailingNullsLength(bytes);

		Encoding safe = (Encoding)encoding.Clone();
		safe.DecoderFallback = DecoderFallback.ReplacementFallback;
		safe.EncoderFallback = EncoderFallback.ReplacementFallback;

		return safe.GetString(bytes, 0, trimmedLen);
	}

	private static bool LooksLikeUnity(string s)
	{
		if (string.IsNullOrEmpty(s))
			return false;

		return s.StartsWith("Unity", StringComparison.Ordinal) ||
			   string.Equals(s, "Unity", StringComparison.Ordinal);
	}

	private bool TryGetLiteralRange(Il2CppStringLiteral lit, out int pos, out int len, out string? reason)
	{
		reason = null;
		pos = 0;
		len = 0;

		if (lit.length > int.MaxValue)
		{
			reason = $"length too large ({lit.length})";
			return false;
		}

		ulong pos64 = (ulong)_header.stringLiteralDataOffset + (ulong)lit.dataIndex;
		ulong end64 = pos64 + (ulong)lit.length;

		if (pos64 > (ulong)_metaData.Length)
		{
			reason = $"data position out of bounds (pos={pos64}, buf={_metaData.Length})";
			return false;
		}

		if (end64 > (ulong)_metaData.Length)
		{
			reason = $"range out of bounds (pos={pos64}, len={lit.length}, buf={_metaData.Length})";
			return false;
		}

		pos = (int)pos64;
		len = (int)lit.length;
		return true;
	}

	private static int TrimTrailingNullsLength(byte[] bytes)
	{
		int end = bytes.Length;
		while (end > 0 && bytes[end - 1] == 0)
			end--;
		return end;
	}

	private static uint ReadUInt32LE(byte[] buffer, int offset)
	{
		if ((uint)offset > buffer.Length - 4u)
			throw new InvalidOperationException("Attempted to read uint32 outside the buffer.");

		return BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
	}

	private static int ReadInt32LE(byte[] buffer, int offset)
	{
		if ((uint)offset > buffer.Length - 4u)
			throw new InvalidOperationException("Attempted to read int32 outside the buffer.");
		return BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(offset, 4));
	}

	private readonly record struct Il2CppGlobalMetadataHeader(
		int stringLiteralOffset,
		int stringLiteralSize,
		int stringLiteralDataOffset,
		int StringOffset,
		int StringSize
	);

	private readonly record struct Il2CppStringLiteral(
		uint length,
		uint dataIndex
	);
}
