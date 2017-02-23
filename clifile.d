module clifile;

import std.ascii;
import std.base64;
import std.conv;
import std.datetime;
import std.range;
import std.string;
import std.traits;

import ae.sys.windows.imports;
import ae.utils.array;
import ae.utils.time.format;

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

import ae.sys.windows.pe.pe;

struct CLIFile
{
	struct Header
	{
		IMAGE_DOS_HEADER dosHeader = cliDosHeader;
		ubyte[] dosStub = cliDosStub;
		IMAGE_NT_HEADERS32 peHeader = cliPEHeader;
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
		header.peHeader = *pe.ntHeaders;

		// IMAGE_OPTIONAL_HEADER's IMAGE_DATA_DIRECTORY array is
		// fixed-length, however the header specifies a variable
		// number of entries. Thus, we ignore them and serialize them
		// separately.

		header.peHeader.OptionalHeader.DataDirectory[] = IMAGE_DATA_DIRECTORY.init; // Don't serialize
		header.dataDirectories = pe.dataDirectories;

		header.sections = pe.sectionHeaders;

		bool[] byteUsed = new bool[bytes.length];

		// Mark header as used
		byteUsed[0 .. cast(ubyte*)(pe.sectionHeaders.ptr + pe.sectionHeaders.length) - bytes.ptr] = true;

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
				unaccountedData ~= UnaccountedBlock(start, bytes[start .. offset-start]);
			}
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

struct HexIntegerSerializer
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		d.writer.putValue("0x%X".format(field));
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

/// Constants which are not declared as an actual enum.
struct ImplicitEnumSerializer(members...)
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		switch (field)
		{
			foreach (i, member; members)
			{
				case member:
					d.writer.putValue(__traits(identifier, members[i]));
					return;
			}
			default:
				d.writer.putValue("%d".format(field));
		}
	}
}

/// An array which might as well be a struct with all fields of the same type.
/// Note: the array length is not represented (because entries with
/// default values are omitted), and must be fixed or specified elsewhere.
struct SparseNamedIndexedArraySerializer(members...)
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.writer.beginStruct();
		foreach (i, ref a; field)
		{
			auto aDef = i < def.length ? def[i] : typeof(a).init;
			if (a == aDef)
				continue;
		label:
			switch (i)
			{
				foreach (memberIndex, member; members)
				{
					case member:
						d.writer.beginTag(__traits(identifier, members[memberIndex]));
						break label;
				}
				default:
					d.writer.beginTag(text(i));
			}
			d.putVar!(typeof(a))(a, aDef);
			d.writer.endTag();
		}
		d.writer.endStruct();
	}
}

/// Bitmask using constants which are not declared as an actual enum.
struct ImplicitEnumBitmaskSerializer(members...)
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		Unqual!F remainingBits = field;
		foreach (i, member; members)
			if ((remainingBits & member) == member)
			{
				d.writer.putValue(__traits(identifier, members[i]));
				remainingBits &= ~member;
			}
		for (Unqual!F mask = 1; mask; mask <<= 1)
			if (remainingBits & mask)
				d.writer.putValue("0x%x".format(mask));
	}
}

/// Unix timestamp serializer.
struct UnixTimestampSerializer
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		SysTime time = SysTime.fromUnixTime(field);
		d.writer.putValue(time.formatTime!"Y-m-d H:i:s");
	}
}

/// Serializer for unions. fieldIndex indicates the index of the union
/// field we will be looking at.
struct UnionSerializer(uint fieldIndex)
{
	void putValue(F, D)(Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.writer.beginStruct();
		foreach (i, ref f; field.tupleof)
			static if (i == fieldIndex)
			{
				enum name = __traits(identifier, field.tupleof[i]);
				d.writer.beginTag(name);
				getSerializer!(F, name).putValue(d, f, def.tupleof[i]);
				d.writer.endTag();
			}
		d.writer.endStruct();
	}
}

auto getSerializer(T, string name)()
{
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "TimeDateStamp")
		return UnixTimestampSerializer();
	else
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "SizeOfOptionalHeader")
		return HexIntegerSerializer();
	else
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "Characteristics")
		return ImplicitEnumBitmaskSerializer!(
			IMAGE_FILE_RELOCS_STRIPPED,
			IMAGE_FILE_EXECUTABLE_IMAGE,
			IMAGE_FILE_LINE_NUMS_STRIPPED,
			IMAGE_FILE_LOCAL_SYMS_STRIPPED,
			IMAGE_FILE_AGGRESIVE_WS_TRIM,
			IMAGE_FILE_LARGE_ADDRESS_AWARE,
			IMAGE_FILE_BYTES_REVERSED_LO,
			IMAGE_FILE_32BIT_MACHINE,
			IMAGE_FILE_DEBUG_STRIPPED,
			IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
			IMAGE_FILE_NET_RUN_FROM_SWAP,
			IMAGE_FILE_SYSTEM,
			IMAGE_FILE_DLL,
			IMAGE_FILE_UP_SYSTEM_ONLY,
			IMAGE_FILE_BYTES_REVERSED_HI,
		)();
	else
	static if (is(Unqual!T == IMAGE_OPTIONAL_HEADER) && name.isOneOf("SizeOfCode", "SizeOfInitializedData",
			"AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "SizeOfImage", "SizeOfHeaders"))
		return HexIntegerSerializer();
	else
	static if (is(Unqual!T == IMAGE_OPTIONAL_HEADER) && name == "Subsystem")
		return ImplicitEnumSerializer!(
			IMAGE_SUBSYSTEM_UNKNOWN,
			IMAGE_SUBSYSTEM_NATIVE,
			IMAGE_SUBSYSTEM_WINDOWS_GUI,
			IMAGE_SUBSYSTEM_WINDOWS_CUI,
			IMAGE_SUBSYSTEM_OS2_CUI,
			IMAGE_SUBSYSTEM_POSIX_CUI,
			IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
			IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
			IMAGE_SUBSYSTEM_EFI_APPLICATION,
			IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
			IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
			IMAGE_SUBSYSTEM_EFI_ROM,
			IMAGE_SUBSYSTEM_XBOX,
			IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
		)();
	else
	static if (is(Unqual!T == IMAGE_OPTIONAL_HEADER) && name == "DllCharacteristics")
		return ImplicitEnumBitmaskSerializer!(
			IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
			IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
			IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
			IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
			IMAGE_DLLCHARACTERISTICS_NO_SEH	,
			IMAGE_DLLCHARACTERISTICS_NO_BIND,
			IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
		)();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name == "Characteristics")
		return ImplicitEnumBitmaskSerializer!(
			IMAGE_SCN_TYPE_REG,
			IMAGE_SCN_TYPE_DSECT,
			IMAGE_SCN_TYPE_NOLOAD,
			IMAGE_SCN_TYPE_GROUP,
			IMAGE_SCN_TYPE_NO_PAD,
			IMAGE_SCN_TYPE_COPY,
			IMAGE_SCN_CNT_CODE,
			IMAGE_SCN_CNT_INITIALIZED_DATA,
			IMAGE_SCN_CNT_UNINITIALIZED_DATA,
			IMAGE_SCN_LNK_OTHER,
			IMAGE_SCN_LNK_INFO,
			IMAGE_SCN_TYPE_OVER,
			IMAGE_SCN_LNK_REMOVE,
			IMAGE_SCN_LNK_COMDAT,
			IMAGE_SCN_MEM_FARDATA,
			IMAGE_SCN_GPREL,
			IMAGE_SCN_MEM_PURGEABLE,
		//	IMAGE_SCN_MEM_16BIT,
			IMAGE_SCN_MEM_LOCKED,
			IMAGE_SCN_MEM_PRELOAD,
			IMAGE_SCN_LNK_NRELOC_OVFL,
			IMAGE_SCN_MEM_DISCARDABLE,
			IMAGE_SCN_MEM_NOT_CACHED,
			IMAGE_SCN_MEM_NOT_PAGED,
			IMAGE_SCN_MEM_SHARED,
			IMAGE_SCN_MEM_EXECUTE,
			IMAGE_SCN_MEM_READ,
			IMAGE_SCN_MEM_WRITE,

			// These bits are not a bitmask, so sort them from most to least bits,
			// so that the member with most bits gets used first
			// 3 bits
			IMAGE_SCN_ALIGN_64BYTES,          // 0x00700000
			IMAGE_SCN_ALIGN_1024BYTES,        // 0x00B00000
			IMAGE_SCN_ALIGN_4096BYTES,        // 0x00D00000
			IMAGE_SCN_ALIGN_8192BYTES,        // 0x00E00000
			// 2 bits
			IMAGE_SCN_ALIGN_4BYTES,           // 0x00300000
			IMAGE_SCN_ALIGN_16BYTES,          // 0x00500000
			IMAGE_SCN_ALIGN_32BYTES,          // 0x00600000
			IMAGE_SCN_ALIGN_256BYTES,         // 0x00900000
			IMAGE_SCN_ALIGN_512BYTES,         // 0x00A00000
			IMAGE_SCN_ALIGN_2048BYTES,        // 0x00C00000
			// 1 bit
			IMAGE_SCN_ALIGN_1BYTES,           // 0x00100000
			IMAGE_SCN_ALIGN_2BYTES,           // 0x00200000
			IMAGE_SCN_ALIGN_8BYTES,           // 0x00400000
			IMAGE_SCN_ALIGN_128BYTES,         // 0x00800000
		)();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name == "Name")
		return CStrArrSerializer();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name.isOneOf("VirtualAddress", "SizeOfRawData", "PointerToRawData"))
		return HexIntegerSerializer();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name == "Misc")
		return UnionSerializer!1(); // VirtualSize
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER._Misc) && name == "VirtualSize")
		return HexIntegerSerializer();
	else
	static if (is(Unqual!T == CLIFile.Header) && name == "dataDirectories")
		return SparseNamedIndexedArraySerializer!(
			IMAGE_DIRECTORY_ENTRY_EXPORT,
			IMAGE_DIRECTORY_ENTRY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_RESOURCE,
			IMAGE_DIRECTORY_ENTRY_EXCEPTION,
			IMAGE_DIRECTORY_ENTRY_SECURITY,
			IMAGE_DIRECTORY_ENTRY_BASERELOC,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
			IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
			IMAGE_DIRECTORY_ENTRY_TLS,
			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
			IMAGE_DIRECTORY_ENTRY_IAT,
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
		)();
	else
	static if (is(Unqual!T == IMAGE_DATA_DIRECTORY) && name.isOneOf("VirtualAddress", "Size"))
		return HexIntegerSerializer();
	else
	static if (is(Unqual!T == CLIFile.UnaccountedBlock) && name == "offset")
		return HexIntegerSerializer();
	else
		return DefaultSerializer();
}

private static immutable initOf(T) = T.init;

struct Disassembler
{
	string disassemble()
	{
		writer.beginTag("file");
		putVar(*file);
		writer.endTag();
		return writer.buf.data;
	}

private:
	const(CLIFile)* file;

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
			static assert(false, "Can't serialize a union: " ~ T.stringof);
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
		static if (is(T : const(ubyte)[]))
			writer.putData(var);
		else
		static if (is(T A : A[]))
		{
			writer.beginStruct();
			foreach (i, ref A a; var)
			{
				writer.beginTag(Unqual!A.stringof);
				auto aDef = i < def.length ? def[i] : A.init;
				if (a != aDef)
					putVar!A(a, aDef);
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

	void putData(in ubyte[] s)
	{
		buf.put(" [");
		// TODO: Don't allocate
		if (s.length <= 64)
			buf.put(Base64.encode(s));
		else
		{
			buf.put("\n");
			indent++;
			foreach (c; s.chunks(48))
			{
				putIndent();
				buf.put(Base64.encode(c));
				buf.put("\n");
			}
			indent--;
			putIndent();
		}
		buf.put("]");
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
	auto cli = CLIFile(cast(ubyte[])read("test.exe"));
	auto disassembler = Disassembler(&cli);
	write("test.rcli", disassembler.disassemble());
}
