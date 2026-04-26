using System.Diagnostics;

namespace AceMetaUnpack;

internal static class Program
{
	private sealed class Args
	{
		public string Input { get; private set; } = "GameAssembly.dll";
		public string Output { get; private set; } = "global-metadata.dat";

		public static Args Parse(string[] argv)
		{
			var args = new Args();

			for (int i = 0; i < argv.Length; i++)
			{
				var a = argv[i];

				if (a is "--help" or "-h" or "/?")
				{
					PrintHelp();
					Environment.Exit(0);
				}

				if (!a.StartsWith("-", StringComparison.Ordinal))
				{
					if (string.Equals(args.Input, "GameAssembly.dll", StringComparison.Ordinal) && i == 0)
					{
						args.Input = a;
						continue;
					}

					if (string.Equals(args.Output, "global-metadata.dat", StringComparison.Ordinal) && i == 1)
					{
						args.Output = a;
						continue;
					}
				}
			}

			if (argv.Length >= 1 && !IsFlag(argv[0]) && !string.IsNullOrWhiteSpace(argv[0]))
				args.Input = argv[0];

			if (argv.Length >= 2 && !IsFlag(argv[1]) && !string.IsNullOrWhiteSpace(argv[1]))
				args.Output = argv[1];

			return args;
		}

		private static bool IsFlag(string s) => s.StartsWith("-", StringComparison.Ordinal) || s.StartsWith("/", StringComparison.Ordinal);

		private static void PrintHelp()
		{
			Console.WriteLine("AceMetaUnpack");
			Console.WriteLine();
			Console.WriteLine("Usage:");
			Console.WriteLine("  AceMetaUnpack [INPUT] [OUTPUT] [--no-print]");
			Console.WriteLine();
			Console.WriteLine("Arguments:");
			Console.WriteLine("  INPUT     Path to GameAssembly.dll (default: GameAssembly.dll)");
			Console.WriteLine("  OUTPUT    Output file path for decrypted metadata (default: global-metadata.dat)");
			Console.WriteLine();
		}
	}

	public static int Main(string[] argv)
	{
		try
		{
			var args = Args.Parse(argv);

			Console.WriteLine("Starting...");
			Console.WriteLine($"Input : {args.Input}");
			Console.WriteLine($"Output: {args.Output}");
			Console.WriteLine();

			byte[] encrypted;
			try
			{
				Console.WriteLine("Extracting encrypted data...");
				var extractor = new Extractor(args.Input);
				extractor.Process();
				encrypted = extractor.GetValidData();
				Console.WriteLine($"Encrypted data length: {encrypted.Length} bytes");
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("Failed during extraction.");
				Console.Error.WriteLine(ex.Message);
				return 1;
			}

			byte[] decrypted;
			var sw = Stopwatch.StartNew();
			try
			{
				Console.WriteLine("Decrypting...");
				decrypted = Xxtea.Decrypt(encrypted, Key);
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("Failed during decryption.");
				Console.Error.WriteLine(ex.Message);
				return 1;
			}
			finally
			{
				sw.Stop();
			}

			Console.WriteLine($"Decryption completed in {sw.Elapsed.TotalMilliseconds:F0} ms");
			Console.WriteLine($"Decrypted length: {decrypted.Length} bytes");
			Console.WriteLine();

			try
			{
				var processor = new Processor(decrypted);

				// ACE momento...
				processor.Initialize();
				processor.EnsureStringLiteralsPatchedIfNeeded();
				// Relevant only on Reverse: 1999. Kept here for completeness
				//processor.DecryptMetadataStrings();
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("Failed while processing string literals.");
				Console.Error.WriteLine(ex.Message);
				return 1;
			}

			try
			{
				File.WriteAllBytes(args.Output, decrypted);
				Console.WriteLine($"Wrote output file: {args.Output}");
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine("Failed to write output file.");
				Console.Error.WriteLine(ex.Message);
				return 1;
			}

			Console.WriteLine("Done.");
			return 1;
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine("Fatal error.");
			Console.Error.WriteLine(ex.ToString());
			return 1;
		}
	}

	private static readonly byte[] Key = { (byte)'E', (byte)'8', (byte)'F', (byte)'F' };
}
