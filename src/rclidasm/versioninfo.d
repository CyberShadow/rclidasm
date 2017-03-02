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

module rclidasm.versioninfo;

import ae.utils.array;

import std.algorithm.searching;
import std.array;
import std.conv;
import std.exception;
import std.string;

struct VersionInfoNode
{
	wchar[] key;
	ushort type;
	const(ubyte)[] value;
	VersionInfoNode[] children;

	@property string valueText()
	{
		if (!value.length)
			return null;
		auto str = cast(wchar[])value;
		enforce(str.endsWith("\0"w), "Not null-terminated");
		return str[0..$-1].to!string;
	}
}

struct VersionInfoParser
{
	const(ubyte)[] data;
	bool[] byteUsed;

	this(in ubyte[] data, bool[] byteUsed)
	{
		enforce((cast(size_t)data.ptr) % 4 == 0, "Data must be DWORD-aligned");
		this.data = data;
		this.byteUsed = byteUsed;
	}

	VersionInfoNode* parse()
	{
		if (!data.length)
			return null;
		return [readNode()].ptr;
	}

	VersionInfoNode readNode()
	{
		auto size = read!ushort() - ushort.sizeof;
		enforce(size <= data.length, "End of data reached reading ");
		auto remainingData = data[size..$];
		scope(success) data = remainingData;
		data = data[0..size];

		auto valueLength = read!ushort();
		auto type = read!ushort();
		if (type)
			valueLength *= 2;

		wchar[] key;
		const(ubyte)[] value;
		debug (verparse) scope(failure) stderr.writefln("wLength=%d wValueLength=%d remainder=%d wType=%d key=%(%s%) [error]", size, valueLength, data.length, type, [key]);
		if (valueLength < data.length && (cast(wchar[])data[0..$-valueLength]).indexOf('\0') < 0)
		{
			// Work around resource compiler bug
			debug (verparse) stderr.writeln("Resource compiler bug detected");
			valueLength += 2; // Make up for the lost null terminator
			auto wdata = cast(wchar[])data;
			while (wdata.length > 1 && wdata[$-1] == 0 && wdata[$-2] == 0)
				wdata = wdata[0..$-1];
			auto point = wdata.length - valueLength/wchar.sizeof;
			key = wdata[0..point];
			value = cast(ubyte[])wdata[point..$];
			data = null;
		}
		else
		{
			key = readWStringz();
			readAlign();
			if (valueLength > data.length)
				valueLength = data.length.to!ushort; // Work around Borland linker bug (madCHook.dll)
			value = readBytes(valueLength);
			readAlign();
		}

		debug (verparse)
		{
			stderr.writefln("wLength=%d wValueLength=%d remainder=%d wType=%d key=%(%s%)", size, valueLength, data.length, type, [key]);
			if (value.length)
				stderr.writeln(hexDump(value));
		}

		VersionInfoNode node;
		node.key = key;
		node.type = type;
		node.value = value;

		while (data.length)
		{
			node.children ~= readNode();
			readAlign();
		}

		return node;
	}

	T read(T)()
	{
		enforce(data.length >= T.sizeof, "End of data reached reading VersionInfo");
		T value = *cast(T*)data.ptr;
		data = data[T.sizeof..$];
		return value;
	}

	wchar[] readWStringz()
	{
		auto start = cast(wchar*)data.ptr;
		size_t count = 0;
		while (read!wchar())
			count++;
		return start[0..count];
	}

	const(ubyte)[] readBytes(size_t count, bool used = true)
	{
		auto result = data[0..count];
		enforce(count <= data.length, "End of data reached reading VersionInfo");
		data = data[count..$];
		if (used)
			byteUsed[0..count] = true;
		byteUsed = byteUsed[count..$];
		return result;
	}

	void readAlign()
	{
		while (data.length && (cast(size_t)data.ptr) % 4 != 0)
			readBytes(1, false);
	}
}

struct VersionInfoCompiler
{
	this(in VersionInfoNode* root)
	{
		this.root = root;
	}

	ubyte[] compile()
	{
		return compileNode(*root);
	}

private:
	const VersionInfoNode* root;

	ubyte[] compileNode(in ref VersionInfoNode node)
	{
		Appender!(ubyte[]) data;
		write(data, ushort(0)); // size - filled in at the end

		if (node.type == 0)
			write(data, node.value.length.to!ushort);
		else
		{
			enforce(node.value.length % 2 == 0, "Invalid value length");
			write(data, (node.value.length / 2).to!ushort);
		}
		write(data, node.type);

		writeWStringz(data, node.key);
		writeAlign(data);
		write(data, node.value);
		writeAlign(data);

		foreach (ref child; node.children)
		{
			write(data, compileNode(child));
			writeAlign(data);
		}

		ushort size = data.data.length.to!ushort;
		data.data[0..ushort.sizeof] = size.bytes;

		return data.data;
	}

	void writeAlign(ref Appender!(ubyte[]) data)
	{
		while (data.data.length % 4 != 0)
			write(data, ubyte(0));
	}

	void writeWStringz(ref Appender!(ubyte[]) data, in wchar[] value)
	{
		write(data, value);
		write(data, wchar(0));
	}

	void write(T)(ref Appender!(ubyte[]) data, in T value)
	{
		data.put(value.bytes);
	}
}
