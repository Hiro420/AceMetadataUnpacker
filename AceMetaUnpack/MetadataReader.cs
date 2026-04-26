using System.Buffers.Binary;

namespace AceMetaUnpack;

internal sealed class MetadataReader
{
	private readonly byte[] _buffer;

	public MetadataReader(byte[] buffer)
	{
		_buffer = buffer ?? throw new ArgumentNullException(nameof(buffer));
	}

	public uint Position { get; set; }

	public uint Length => (uint)_buffer.Length;

	public void Seek(uint position)
	{
		if (position > Length)
			throw new ArgumentOutOfRangeException(nameof(position), "Position is beyond end of buffer.");
		Position = position;
	}

	public byte ReadByte()
	{
		EnsureAvailable(1);
		return _buffer[Position++];
	}

	public uint ReadUInt32()
	{
		EnsureAvailable(4);
		uint value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.AsSpan((int)Position, 4));
		Position += 4;
		return value;
	}

	public int ReadInt32()
	{
		EnsureAvailable(4);
		int value = BinaryPrimitives.ReadInt32LittleEndian(_buffer.AsSpan((int)Position, 4));
		Position += 4;
		return value;
	}

	public byte[] ReadBytes(int count)
	{
		if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
		EnsureAvailable((uint)count);

		var dst = new byte[count];
		Buffer.BlockCopy(_buffer, (int)Position, dst, 0, count);
		Position += (uint)count;
		return dst;
	}

	public T[] ReadArray<T>(uint offset, uint byteSize, Func<MetadataReader, T> readOne)
	{
		if (readOne is null) throw new ArgumentNullException(nameof(readOne));
		if (byteSize == 0) return Array.Empty<T>();

		if (offset > Length || byteSize > Length - offset)
			throw new InvalidOperationException($"Array range out of bounds (offset={offset}, size={byteSize}).");

		Seek(offset);

		uint start = Position;
		T first = readOne(this);
		uint elementSize = Position - start;
		if (elementSize == 0)
			throw new InvalidOperationException("readOne() consumed 0 bytes; cannot determine element size.");

		uint count = byteSize / elementSize;

		Seek(offset);

		var result = new T[count];
		for (int i = 0; i < result.Length; i++)
			result[i] = readOne(this);

		return result;
	}

	private void EnsureAvailable(uint bytes)
	{
		if (Position > Length || bytes > Length - Position)
			throw new InvalidOperationException("Attempted to read beyond end of metadata buffer.");
	}
}
