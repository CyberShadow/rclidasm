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

module rclidasm.resources;

import std.algorithm.searching;
import std.conv;
import std.exception;

import ae.sys.windows.imports;
import ae.utils.array;

mixin(importWin32!(q{winnt}));

struct ResourceDirectory
{
	// Mix in IMAGE_RESOURCE_DIRECTORY's fields
	mixin(mixStruct!IMAGE_RESOURCE_DIRECTORY);

	ResourceDirectoryEntry[] entries;
}

struct ResourceDirectoryEntry
{
	bool NameIsString;
	WCHAR[] Name;
	union
	{
		DWORD NameOffset;
		DWORD Id;
	}

	bool DataIsDirectory;
	DWORD OffsetToData;
	union
	{
		ResourceDirectory directory;
		ResourceDataEntry data;
	}
}

struct ResourceDataEntry
{
	// Mix in IMAGE_RESOURCE_DIRECTORY's fields
	// Note: OffsetToData is relative to resource block start (like
	// every other offset in resources), instead of being an RVA (like
	// in the actual resources)
	mixin(mixStruct!IMAGE_RESOURCE_DATA_ENTRY);

	ubyte[] data;
}

struct ResourceParser
{
	this(void[] data, bool[] byteUsed, uint rva)
	{
		this.data = cast(ubyte[])data;
		this.byteUsed = byteUsed;
		this.rva = rva;
		assert(data.length == byteUsed.length);
	}

	ResourceDirectory parse()
	{
		return readDirectory(0);
	}

private:
	ubyte[] data;
	bool[] byteUsed;
	uint rva;

	ResourceDirectory readDirectory(uint offset)
	{
		enforce(offset + IMAGE_RESOURCE_DIRECTORY.sizeof <= data.length, "Out-of-bounds directory offset");
		auto winDir = cast(IMAGE_RESOURCE_DIRECTORY*)(data.ptr + offset);
		ResourceDirectory dir;
		foreach (i, ref f; (*winDir).tupleof)
			__traits(getMember, dir, __traits(identifier, IMAGE_RESOURCE_DIRECTORY.tupleof[i])) = f;
		dir.entries.length = winDir.NumberOfNamedEntries + winDir.NumberOfIdEntries;

		byteUsed[offset..offset + IMAGE_RESOURCE_DIRECTORY.sizeof] = true;
		offset += IMAGE_RESOURCE_DIRECTORY.sizeof;
		enforce(offset + dir.entries.length * IMAGE_RESOURCE_DIRECTORY_ENTRY.sizeof <= data.length, "Not enough data for directory entries");
		auto winEntries = cast(IMAGE_RESOURCE_DIRECTORY_ENTRY*)(data.ptr + offset)[0..dir.entries.length];
		byteUsed[offset..offset + dir.entries.length * IMAGE_RESOURCE_DIRECTORY_ENTRY.sizeof] = true;

		foreach (n; 0..dir.entries.length)
		{
			auto winEntry = &winEntries[n];
			auto entry = &dir.entries[n];

			entry.NameIsString = winEntry.NameIsString;
			if (winEntry.NameIsString)
			{
				entry.NameOffset = winEntry.NameOffset;
				entry.Name = readString(winEntry.NameOffset);
			}
			else
				entry.Id = winEntry.Name; // Use .Name instead of .Id to save all 32 bits

			entry.DataIsDirectory = winEntry.DataIsDirectory;
			if (entry.DataIsDirectory)
			{
				entry.directory = readDirectory(winEntry.OffsetToDirectory);
				entry.OffsetToData = winEntry.OffsetToDirectory;
			}
			else
			{
				entry.data = readDirectoryData(winEntry.OffsetToData);
				entry.OffsetToData = winEntry.OffsetToData;
			}
		}

		return dir;
	}

	ResourceDataEntry readDirectoryData(uint offset)
	{
		enforce(offset + IMAGE_RESOURCE_DATA_ENTRY.sizeof <= data.length, "Out-of-bounds directory data header offset");
		auto winDirData = cast(IMAGE_RESOURCE_DATA_ENTRY*)(data.ptr + offset);
		byteUsed[offset..offset + IMAGE_RESOURCE_DATA_ENTRY.sizeof] = true;
		ResourceDataEntry dirData;
		foreach (i, ref f; (*winDirData).tupleof)
			__traits(getMember, dirData, __traits(identifier, IMAGE_RESOURCE_DATA_ENTRY.tupleof[i])) = f;
		dirData.OffsetToData -= rva; // Make serialized representation relative to the resource section start
		auto start = dirData.OffsetToData;
		enforce(start + winDirData.Size <= data.length, "Out-of-bounds directory data offset");
		dirData.data = data[start .. start + winDirData.Size];
		byteUsed[start .. start + winDirData.Size] = true;

		return dirData;
	}

	WCHAR[] readString(uint offset)
	{
		enforce(offset + typeof(IMAGE_RESOURCE_DIR_STRING_U.Length).sizeof <= data.length, "Out-of-bounds string offset");
		auto winStr = cast(IMAGE_RESOURCE_DIR_STRING_U*)(data.ptr + offset);
		auto strOffset = offset + typeof(IMAGE_RESOURCE_DIR_STRING_U.Length).sizeof;
		auto strEnd = strOffset + winStr.Length * WCHAR.sizeof;
		enforce(strEnd <= data.length, "Out-of-bounds string offset");
		byteUsed[offset .. strEnd] = true;
		auto firstChar = &winStr._NameString;
		return firstChar[0..winStr.Length];
	}
}

struct ResourceCompiler
{
	this(ref in ResourceDirectory root, uint rva)
	{
		this.root = root;
		this.rva = rva;
	}

	ubyte[] compile()
	{
		putDirectory(root, 0);
		return data;
	}

private:
	const ResourceDirectory root;
	ubyte[] data;
	bool[] byteUsed;
	uint rva;

	void putDirectory(in ref ResourceDirectory dir, size_t offset)
	{
		IMAGE_RESOURCE_DIRECTORY winDir;
		foreach (i, ref f; winDir.tupleof)
			f = __traits(getMember, dir, __traits(identifier, IMAGE_RESOURCE_DIRECTORY.tupleof[i]));
		putBytes(winDir.bytes, offset);
		offset += winDir.sizeof;

		enforce(dir.NumberOfNamedEntries + dir.NumberOfIdEntries == dir.entries.length, "Mismatching entry count");

		foreach (ref entry; dir.entries)
		{
			IMAGE_RESOURCE_DIRECTORY_ENTRY winEntry;

			winEntry.NameIsString = entry.NameIsString;
			if (winEntry.NameIsString)
			{
				winEntry.NameOffset = entry.NameOffset;
				putString(entry.Name, entry.NameOffset);
			}
			else
				winEntry.Name = entry.Id; // Use .Name instead of .Id to restore all 32 bits

			winEntry.DataIsDirectory = entry.DataIsDirectory;
			if (entry.DataIsDirectory)
			{
				winEntry.OffsetToDirectory = entry.OffsetToData;
				putDirectory(entry.directory, winEntry.OffsetToDirectory);
			}
			else
			{
				winEntry.OffsetToData = entry.OffsetToData;
				putDirectoryData(entry.data, winEntry.OffsetToData);
			}

			putBytes(winEntry.bytes, offset);
			offset += winEntry.sizeof;
		}
	}

	void putDirectoryData(in ref ResourceDataEntry dirData, size_t offset)
	{
		IMAGE_RESOURCE_DATA_ENTRY winData;
		foreach (i, ref f; winData.tupleof)
			f = __traits(getMember, dirData, __traits(identifier, IMAGE_RESOURCE_DATA_ENTRY.tupleof[i]));
		winData.OffsetToData += rva; // Serialized representation is relative to the resource section start
		putBytes(winData.bytes, offset);
		putBytes(dirData.data, dirData.OffsetToData);
	}

	void putString(in WCHAR[] str, size_t offset)
	{
		IMAGE_RESOURCE_DIR_STRING_U winStr;
		winStr.Length = str.length.to!(typeof(winStr.Length));
		putBytes(winStr.bytes[0..typeof(winStr.Length).sizeof], offset);
		putBytes(str.bytes, offset + typeof(winStr.Length).sizeof);
	}

	void putBytes(in ubyte[] bytes, size_t offset)
	{
		if (data.length < offset + bytes.length)
			data.length = byteUsed.length = offset + bytes.length;
		auto use = byteUsed[offset .. offset + bytes.length];
		enforce(!use.canFind(true), "Overlapping resource data");
		data[offset .. offset + bytes.length] = bytes;
		use[] = true;
	}
}

private:

/// Generate code for declarations of all of the type's fields.
string mixStruct(T)()
{
	string s;
	foreach (i, f; T.init.tupleof)
		s ~= typeof(f).stringof ~ " " ~ __traits(identifier, T.tupleof[i]) ~ ";";
	return s;
}
