namespace AceMetaUnpack;

internal readonly record struct Il2CppGlobalMetadataHeader(
	uint stringLiteralOffset,
	uint stringLiteralSize,
	uint stringLiteralDataOffset
);

internal readonly record struct Il2CppStringLiteral(
	uint length,
	uint dataIndex
);
