module cilfile;

import std.ascii;
import std.conv;
import std.string;
import std.traits;

/*

struct MSDosHeader
{
	ubyte[0x3C] part1 = [
		0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	];
	uint lfanew = MSDosHeader.sizeof;
	ubyte[0x40] part2 = [
		0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd,
		0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72,
		0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
		0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e,
		0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
		0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	];
}

static assert(MSDosHeader.sizeof == 0x80);
static assert(MSDosHeader.init.lfanew == 0x80);

struct PEFileHeader
{
	enum Characteristics : ushort
	{
		IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
		IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
		IMAGE_FILE_32BIT_MACHINE = 0x0100,
		IMAGE_FILE_DLL = 0x2000,
	}

	char[4] magic = "PE\0\0";
	ushort machine = 0x14c;
	ushort numSections;
	int fileDate;
	uint symbolTablePointer, numSymbols;
	ushort optionalHeaderSize;
	Characteristics characteristics;
}

struct PEOptionalHeader
{
	enum Subsystem : ushort
	{
		IMAGE_SUBSYSTEM_WINDOWS_GUI = 0x02,
		IMAGE_SUBSYSTEM_WINDOWS_CUI = 0x03,
	}
		
	// Standard fields
	ushort magic = 0x010B;
	ubyte lMajor = 6;
	ubyte lMinor = 0;
	uint codeSize;
	uint initializeDataSize;
	uint uninitializeDataSize;
	uint entryPointRVA;
	uint baseOfCode;
	uint baseOfData;

	// NT fields
	uint imageBase;
	uint sectionAlignment;
	uint fileAlignment = 0x200;
	ushort osMajor = 5;
	ushort osMinor = 0;
	ushort userMajor = 0;
	ushort userMinor = 0;
	ushort subSysMajor = 5;
	ushort subSysMinor = 0;
	uint reserved = 0;
	uint imageSize;
	uint headerSize;
	uint fileChecksum = 0;
	Subsystem subsystem;
	ushort dllFlags;
	uint stackReserveSize = 0x100000;
	uint stackCommitSize = 0x1000;
	uint heapReserveSize = 0x100000;
	uint heapCommitSize = 0x1000;
	uint loaderFlags = 0;
	uint numDataDirectories = 0;
}

struct PENTHeader
{
	
}

*/

import ae.sys.windows.imports;
import ae.utils.array;
mixin(importWin32!(q{winnt}));

immutable IMAGE_DOS_HEADER cilDosHeader =
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

immutable ubyte[] cilDosStub =
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

immutable IMAGE_NT_HEADERS32 cilPEHeader =
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
	},
};

import ae.sys.windows.pe.pe;

struct CILFile
{
	struct Header
	{
		IMAGE_DOS_HEADER dosHeader = cilDosHeader;
		ubyte[] dosStub = cilDosStub;
		IMAGE_NT_HEADERS32 peHeader = cilPEHeader;
		IMAGE_DATA_DIRECTORY[] dataDirectories;
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

	this(void[] bytes)
	{
		auto pe = PE(bytes);
		header.dosHeader = *pe.dosHeader;
		// TODO dosStub
		header.peHeader = *pe.ntHeaders;
		// TODO header.dataDirectories =
		header.sections = pe.sectionHeaders;
	}
}

struct DefaultSerializer
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.putVar!(typeof(field))(field, def);
	}
}

/// For zero-terminated strings in fixed-length arrays.
struct CStrArrSerializer
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		auto arr = field[];
		while (arr.length && arr[$-1] == 0)
			arr = arr[0..$-1];
		d.writer.putString(cast(char[])arr);
	}
}

auto getSerializer(T, string name)()
{
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name == "Name")
		return CStrArrSerializer();
	else
		return DefaultSerializer();
}

private static immutable initOf(T) = T.init;

struct Disassembler
{
	string disassemble()
	{
		writer.beginTag("header");
		putVar(file.header);
		writer.endTag();
		return writer.buf.data;
	}

private:
	const(CILFile)* file;

	Writer writer;

	void putVar(T)(ref T var, in ref T def = initOf!T)
	{
		static if (is(T == struct))
		{
			writer.beginStruct();
			foreach (i, ref f; var.tupleof)
			{
				if (f == def.tupleof[i])
					continue;

				enum name = __traits(identifier, var.tupleof[i]);
				writer.beginTag(name);
				getSerializer!(T, name).putValue(this, f, def.tupleof[i]);
				writer.endTag();
			}
			writer.endStruct();
		}
		else
		static if (is(T == union))
		{
			// TODO
		}
		else
		static if (is(T : ulong))
		{
			writer.putValue(text(var)); // TODO: Don't allocate
		}
		else
		static if (is(T == string))
		{
			writer.putString(var);
		}
		else
		static if (is(T A : A[]))
		{
			writer.beginStruct();
			foreach (ref A a; var)
			{
				writer.beginTag(Unqual!A.stringof);
				putVar(a);
				writer.endTag();
			}
			writer.endStruct();
		}
		else
			static assert(false, "Don't know how to put " ~ T.stringof);
	}
}

struct Writer
{
	void beginTag(string s)
	{
		putIndent();
		debug foreach (char c; s)
			assert(isAlphaNum(c) || c.isOneOf("._"), "Bad tag name: " ~ s);
		buf.put(s);
	}

	void endTag()
	{
		buf.put("\n");
	}

	void beginStruct()
	{
		buf.put(" {\n");
		indent++;
	}

	void endStruct()
	{
		indent--;
		putIndent();
		buf.put("}");
	}

	void putValue(in char[] s)
	{
		buf.put(" ");
		buf.put(s);
	}

	void putString(in char[] s)
	{
		// TODO: use WYSIWYG literals when appropriate
		buf.put(` "`);
		foreach (char c; s)
			if (c < 0x20)
				buf.put(`\x%02X`.format(c)); // TODO: Don't allocate
			else
			{
				if (c == '"' || c == '\\')
					buf.put('\\');
				buf.put(c);
			}
		buf.put('"');
	}

private:
	uint indent;

	void putIndent()
	{
		foreach (i; 0..indent)
			buf.put("  ");
	}
	
	import std.array : Appender;
	Appender!string buf;
}

void main()
{
	import std.file;
	auto cil = CILFile(read("Assembly-CSharp.dll"));
	auto disassembler = Disassembler(&cil);
	write("Assembly-CSharp.rcli", disassembler.disassemble());
}
