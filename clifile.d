module clifile;

import std.algorithm.searching;
import std.ascii;
import std.base64;
import std.conv;
import std.datetime;
import std.exception;
import std.range;
import std.string;
import std.traits;

import ae.sys.windows.imports;
import ae.utils.array;

mixin(importWin32!(q{winnt}));

import common;
import disassembler;
import serialization;
import writer;

immutable IMAGE_DOS_HEADER cliDosHeader =
{
	e_magic : 0x5A4D, // MZ
	e_cblp : 0x90,
	e_cp : 3,
	e_cparhdr : 4,
	e_minalloc : 0x0000,
	e_maxalloc : 0xFFFF,
	e_sp : 0x00B8,
	e_lfarlc : 0x0040,
	e_lfanew : 0x00000080,
};

immutable ubyte[] cliDosStub =
[
	0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
	0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
	0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
	0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
	0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

immutable IMAGE_NT_HEADERS32 cliPEHeader =
{
	Signature : 0x00004550, // "PE\0\0"
	FileHeader :
	{
		Machine : 0x014C,
	},
	OptionalHeader :
	{
		Magic : 0x010B,
		MajorLinkerVersion : 6,
		MinorLinkerVersion : 0,
		FileAlignment : 0x200,
		MajorOperatingSystemVersion : 5,
		MinorOperatingSystemVersion : 0,
		MajorSubsystemVersion : 5,
		MinorSubsystemVersion : 0,
		SizeOfStackReserve : 0x100000,
		SizeOfStackCommit : 0x1000,
		SizeOfHeapReserve : 0x100000,
		SizeOfHeapCommit : 0x1000,
		NumberOfRvaAndSizes : 0x10,
	},
};

import ae.sys.windows.pe.pe;

struct CLIFile
{
	size_t size;

	struct Header
	{
		IMAGE_DOS_HEADER dosHeader = cliDosHeader;
		ubyte[] dosStub = cliDosStub;
		IMAGE_NT_HEADERS32 ntHeaders = cliPEHeader;
		IMAGE_DATA_DIRECTORY[] dataDirectories = new IMAGE_DATA_DIRECTORY[16];
		IMAGE_SECTION_HEADER[] sections;

		struct ImportFunction
		{
			ushort hint;
			string name;
		}

		struct ImportModule
		{
			IMAGE_IMPORT_DESCRIPTOR descriptor;
			ImportFunction functions;
		}

		ImportModule[] imports;

		struct Fixup
		{
			ubyte type;
			uint rva;
		}
		Fixup[] fixups;
	}
	Header header;

	// Non-zero data in the PE file that doesn't seem to be referenced
	// by anything.
	struct UnaccountedBlock
	{
		size_t offset;
		ubyte[] data;
	}
	UnaccountedBlock[] unaccountedData;

	this(ubyte[] bytes)
	{
		auto pe = PE(bytes);
		header.dosHeader = *pe.dosHeader;
		if (IMAGE_DOS_HEADER.sizeof < pe.dosHeader.e_lfanew)
			header.dosStub = bytes[IMAGE_DOS_HEADER.sizeof .. pe.dosHeader.e_lfanew];
		header.ntHeaders = *pe.ntHeaders;

		// IMAGE_OPTIONAL_HEADER's IMAGE_DATA_DIRECTORY array is
		// fixed-length, however the header specifies a variable
		// number of entries. Thus, we ignore them and serialize them
		// separately.

		header.ntHeaders.OptionalHeader.DataDirectory[] = IMAGE_DATA_DIRECTORY.init; // Don't serialize
		header.dataDirectories = pe.dataDirectories;

		header.sections = pe.sectionHeaders;

		bool[] byteUsed = new bool[bytes.length];

		// Mark headers as used
		byteUsed[0 .. cast(ubyte*)(pe.dataDirectories.ptr + pe.dataDirectories.length) - bytes.ptr] = true;
		byteUsed[cast(ubyte*)(pe.sectionHeaders.ptr                           ) - bytes.ptr ..
		         cast(ubyte*)(pe.sectionHeaders.ptr + pe.sectionHeaders.length) - bytes.ptr] = true;

		// ...

		// Record unaccounted data
		for (size_t offset = 0; offset < bytes.length; offset++)
			if (!byteUsed[offset] && bytes[offset] != 0)
			{
				auto start = offset;
				while (offset < bytes.length && !byteUsed[offset])
					offset++;
				while (offset > start && bytes[offset-1] == 0)
					offset--;
				unaccountedData ~= UnaccountedBlock(start, bytes[start .. offset]);
			}

		size = bytes.length;
	}

	ubyte[] compile()
	{
		ubyte[] result;
		result ~= header.dosHeader.bytes;
		if (IMAGE_DOS_HEADER.sizeof < header.dosHeader.e_lfanew)
		{
			enforce(header.dosStub.length == header.dosHeader.e_lfanew - IMAGE_DOS_HEADER.sizeof, "DOS stub length / e_lfanew mismatch");
			result ~= header.dosStub;
		}
		result ~= header.ntHeaders.bytes[0 .. IMAGE_NT_HEADERS32.OptionalHeader.offsetof + IMAGE_NT_HEADERS32.OptionalHeader.DataDirectory.offsetof];
		result ~= header.dataDirectories.bytes;
		result.length = header.dosHeader.e_lfanew + header.ntHeaders.OptionalHeader.offsetof + header.ntHeaders.FileHeader.SizeOfOptionalHeader;
		result ~= header.sections.bytes;

		foreach (block; unaccountedData)
		{
			if (result.length < block.offset + block.data.length)
				result.length = block.offset + block.data.length;
			result[block.offset .. block.offset+block.data.length] = block.data;
		}

		result.length = size;

		return result;
	}
}
