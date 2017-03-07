/*
 *  Copyright 2017 Vladimir Panteleev <vladimir@thecybershadow.net>
 *  This file is part of rclidasm.
 *
 *  rclidasm is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  rclidasm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with rclidasm.  If not, see <http://www.gnu.org/licenses/>.
 */

module rclidasm.clifile;

import std.algorithm.iteration;
import std.array;
import std.bitmanip;
import std.conv;
import std.exception;
import std.format;
import std.traits;

import ae.sys.windows.imports;
import ae.sys.windows.pe.pe;
import ae.utils.array;

import rclidasm.common;
import rclidasm.resources;

mixin(importWin32!(q{winnt}));

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
	}
	Header header;

	struct ImportFunction
	{
		ushort hint;
		char[] name;
		uint iltEntry;
		uint iatEntry;
	}
	struct ImportModule
	{
		IMAGE_IMPORT_DESCRIPTOR descriptor;
		char[] name;
		ImportFunction[] functions;
	}
	ImportModule[] imports;

	ResourceDirectory resources;

	struct Fixup
	{
		ubyte type;
		uint rva;
	}
	Fixup[] fixups;

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

		// Parse resources
		if (header.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size)
		{
			auto resData = pe.directoryData(IMAGE_DIRECTORY_ENTRY_RESOURCE);
			auto resAddr = resData.ptr - bytes.ptr;
			assert(resAddr < bytes.length);
			auto parser = ResourceParser(
				resData,
				byteUsed[resAddr .. resAddr + resData.length],
				header.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
			resources = parser.parse();
		}

		// Parse fixups
		if (header.dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto data = pe.directoryData(IMAGE_DIRECTORY_ENTRY_BASERELOC);
			auto addr = data.ptr - bytes.ptr;
			assert(addr < bytes.length);
			byteUsed[addr .. addr + data.length] = true;
			while (data.length >= RelocBlockHeader.sizeof)
			{
				auto header = data[0..RelocBlockHeader.sizeof].fromBytes!RelocBlockHeader;
				enforce(header.BlockSize <= data.length, "Out-of-bounds relocation block size");
				enforce(header.BlockSize > RelocBlockHeader.sizeof, "Invalid relocation block size");
				auto block = data[0..header.BlockSize];
				enforce(block.length % 4 == 0, "Unaligned fixup block");
				auto blockFixups = block[RelocBlockHeader.sizeof..$].fromBytes!(RelocFixup[]);
				if (blockFixups[$-1] == RelocFixup.init)
					blockFixups = blockFixups[0..$-1]; // Trim padding
				foreach (f; blockFixups)
					fixups ~= Fixup(f.Type, header.PageRVA + f.Offset);
				data = data[block.length .. $];
			}
		}

		char[] readStringz(ref size_t rva)
		{
			auto addr = pe.rvaToFile(rva);
			auto start = addr;
			while (addr < bytes.length && bytes[addr])
				addr++;
			rva += (addr - start) + 1; // Advance by string length plus NUL terminator
			byteUsed[start..addr] = true;
			return cast(char[])bytes[start..addr];
		}

		ref T readBytesAt(T)(ref size_t rva, size_t end = size_t.max)
		{
			enforce(rva + T.sizeof <= end, "Address out-of-bounds while trying to read %s".format(T.stringof));
			auto addr = pe.rvaToFile(rva);
			enforce(addr + T.sizeof <= bytes.length, "Offset out-of-bounds while trying to read %s".format(T.stringof));
			byteUsed[addr .. addr + T.sizeof] = true;
			rva += T.sizeof;
			return fromBytes!T(bytes[addr .. addr + T.sizeof]);
		}

		if (header.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			size_t addr = pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			auto end = addr + header.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
			while (true)
			{
				enforce(addr + IMAGE_IMPORT_DESCRIPTOR.sizeof <= end, "End of data reached while trying to read ");
				auto descriptor = readBytesAt!IMAGE_IMPORT_DESCRIPTOR(addr, end);
				if (descriptor == IMAGE_IMPORT_DESCRIPTOR.init)
					break;

				ImportModule importModule;
				importModule.descriptor = descriptor;
				size_t nameAddr = descriptor.Name;
				importModule.name = readStringz(nameAddr);

				size_t iltAddr = descriptor.OriginalFirstThunk;
				size_t iatAddr = descriptor.FirstThunk;

				while (true)
				{
					auto iltEntry = readBytesAt!uint(iltAddr);
					auto iatEntry = readBytesAt!uint(iatAddr);
					if (!iltEntry)
						break;

					ImportFunction importFunction;
					alias Hint = typeof(importFunction.hint); // ushort
					size_t hintNameAddr = iltEntry;
					importFunction.hint = readBytesAt!Hint(hintNameAddr);
					importFunction.name = readStringz(hintNameAddr);
					importFunction.iltEntry = iltEntry;
					importFunction.iatEntry = iatEntry;

					importModule.functions ~= importFunction;
				}

				imports ~= importModule;
			}
		}

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

	ubyte[] compile() const
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

		result.length = size;

		size_t rvaToFile(size_t offset)
		{
			foreach (ref section; header.sections)
				if (offset >= section.VirtualAddress && offset < section.VirtualAddress + section.SizeOfRawData)
					return offset - section.VirtualAddress + section.PointerToRawData;
			throw new Exception("Unmapped memory address");
		}

		if (header.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size)
		{
			auto resRVA = header.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			auto resAddr = rvaToFile(resRVA).to!uint;
			auto resData = ResourceCompiler(resources, resRVA).compile();
			result[resAddr .. resAddr + resData.length] = resData;
		}

		if (fixups.length)
		{
			enforce(header.dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size, "No relocation section");
			auto relRVA = header.dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
			auto relAddr = rvaToFile(relRVA).to!uint;
			ubyte[] relData;
			enum mask = (1<<12)-1;
			foreach (blockFixups; fixups.chunkBy!((Fixup a, Fixup b) => (a.rva & ~mask) == (b.rva & ~mask)))
			{
				auto encoded = blockFixups.map!((ref fixup) { RelocFixup f; f.Type = fixup.type; f.Offset = fixup.rva & mask; return f; }).array.bytes;
				if (encoded.length % 4 != 0)
					encoded ~= initOf!RelocFixup.bytes;
				auto header = RelocBlockHeader(blockFixups.front.rva & ~mask, (RelocBlockHeader.sizeof + encoded.length).to!uint);
				relData ~= header.bytes ~ encoded;
			}
			result[relAddr .. relAddr + relData.length] = relData;
		}

		void put(T)(in ref T value, ref size_t rva, size_t end = size_t.max)
		if (!hasIndirections!T)
		{
			enforce(rva + T.sizeof < end, "Address out-of-bounds while writing %s".format(T.stringof));
			auto addr = rvaToFile(rva);
			enforce(addr + T.sizeof <= result.length, "Offset out-of-bounds while writing %s".format(T.stringof));
			result[addr .. addr + T.sizeof] = value.bytes[];
			rva += T.sizeof;
		}

		void putStringz(in char[] str, ref size_t rva, size_t end = size_t.max)
		{
			foreach (c; str)
				put(c, rva, end);
			char c = 0;
			put(c, rva, end);
		}

		if (imports.length)
		{
			size_t impRVA = enforce(header.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, "No import table section");
			size_t impEnd = impRVA + header.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

			foreach (ref importModule; imports)
			{
				put(importModule.descriptor, impRVA, impEnd);
				size_t nameRVA = importModule.descriptor.Name;
				putStringz(importModule.name, nameRVA);

				size_t iltAddr = importModule.descriptor.OriginalFirstThunk;
				size_t iatAddr = importModule.descriptor.FirstThunk;

				foreach (ref importFunction; importModule.functions)
				{
					put(importFunction.iltEntry, iltAddr);
					put(importFunction.iatEntry, iatAddr);

					size_t hintNameAddr = importFunction.iltEntry;
					put(importFunction.hint, hintNameAddr);
					putStringz(importFunction.name, hintNameAddr);
				}
				put(initOf!uint, iltAddr);
				put(initOf!uint, iatAddr);
			}
			put(initOf!IMAGE_IMPORT_DESCRIPTOR, impRVA, impEnd);
		}

		foreach (block; unaccountedData)
		{
			if (result.length < block.offset + block.data.length)
				result.length = block.offset + block.data.length;
			result[block.offset .. block.offset+block.data.length] = block.data;
		}

		return result;
	}

private:
	struct RelocBlockHeader
	{
		uint PageRVA, BlockSize;
	}

	struct RelocFixup
	{
		mixin(bitfields!(
			ubyte , "Type"  ,  4,
			ushort, "Offset", 12,
		));
	}
}
