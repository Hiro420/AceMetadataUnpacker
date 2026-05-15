namespace AceMetaUnpack;

public sealed class Extractor(string dllPath)
{
	private readonly string _dllPath = dllPath ?? throw new ArgumentNullException(nameof(dllPath));
	private byte[] _validData = [];

	public void Process() => ExtractData();

	public byte[] GetValidData() => (byte[])_validData.Clone();

	private void ExtractData()
	{
		if (!File.Exists(_dllPath))
			throw new FileNotFoundException("DLL not found", _dllPath);

		using FileStream fs = File.OpenRead(_dllPath);
		using BinaryReader reader = new(fs);

		PEHeader.DosHeader dosHeader = new();

		PEHeader.ReadDos(reader, ref dosHeader);
		PEHeader.ReadPe(reader, ref dosHeader);

		if (dosHeader.pe.signature != 0x4550)
			throw new InvalidDataException(
				"Invalid PE signature. The file may be corrupt or not a valid PE file.");

		PEHeader.ReadDataDir(reader, ref dosHeader);
		PEHeader.ReadSections(reader, ref dosHeader);
		PEHeader.ReadDataOffset(ref dosHeader);
		PEHeader.ReadExportDir(reader, ref dosHeader);
		PEHeader.ReadImportDir(reader, ref dosHeader);

		if (dosHeader.dataDirectory is null || dosHeader.section_table is null)
			throw new InvalidDataException(
				"Failed to read PE headers or sections. The file may be corrupt or not a valid PE file.");

		byte[]? metadataResource = PEHeader.ExtractResource(
			reader,
			ref dosHeader,
			new PEHeader.ResourceId("CFG"),
			new PEHeader.ResourceId(130));

		if (metadataResource is null || metadataResource.Length == 0)
			throw new InvalidDataException(
				"Failed to extract resource with ID 130 and type 'CFG'. The resource may be missing or corrupt.");

		_validData = metadataResource;

		PEHeader.Cleanup(ref dosHeader);
	}
}