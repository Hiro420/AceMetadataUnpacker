using System.Runtime.InteropServices;

namespace AceMetaUnpack;

public sealed class Extractor
{
	private readonly string _dllPath;
	private byte[] _validData = Array.Empty<byte>();

	public Extractor(string dllPath)
	{
		_dllPath = dllPath ?? throw new ArgumentNullException(nameof(dllPath));
	}

	public void Process()
	{
		ExtractData();
	}

	public byte[] GetValidData()
	{
		var copy = new byte[_validData.Length];
		Buffer.BlockCopy(_validData, 0, copy, 0, _validData.Length);
		return copy;
	}

	private void ExtractData()
	{
		if (!File.Exists(_dllPath))
			throw new FileNotFoundException("DLL not found", _dllPath);

		IntPtr module = LoadLibraryEx(_dllPath, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
		if (module == IntPtr.Zero)
			throw new Exception($"LoadLibraryEx failed. Win32Error={Marshal.GetLastWin32Error()}");

		try
		{
			IntPtr resInfo = FindResource(module, MAKEINTRESOURCE(130), "CFG");
			if (resInfo == IntPtr.Zero)
				throw new Exception("CFG resource with ID 130 not found");

			uint size = SizeofResource(module, resInfo);
			if (size == 0)
				throw new Exception($"CFG resource ID 130 has zero size. Win32Error={Marshal.GetLastWin32Error()}");

			IntPtr resData = LoadResource(module, resInfo);
			if (resData == IntPtr.Zero)
				throw new Exception($"LoadResource failed. Win32Error={Marshal.GetLastWin32Error()}");

			IntPtr ptr = LockResource(resData);
			if (ptr == IntPtr.Zero)
				throw new Exception("LockResource failed");

			_validData = new byte[size];
			Marshal.Copy(ptr, _validData, 0, checked((int)size));
		}
		finally
		{
			FreeLibrary(module);
		}
	}

	private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;

	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
	private static extern IntPtr FindResource(IntPtr hModule, IntPtr lpName, string lpType);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

	[DllImport("kernel32.dll", SetLastError = false)]
	private static extern IntPtr LockResource(IntPtr hResData);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool FreeLibrary(IntPtr hModule);

	private static IntPtr MAKEINTRESOURCE(int id) => (IntPtr)id;
}
