module rclidasm.serialization;

import std.conv;
import std.datetime;
import std.string;
import std.traits;

import ae.sys.windows.imports;
import ae.utils.array;
import ae.utils.time.format;
import ae.utils.time.parse;

mixin(importWin32!(q{winnt}));

import rclidasm.assembler;
import rclidasm.clifile;
import rclidasm.common;
import rclidasm.disassembler;

struct DefaultRepresentation
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.putVar!(typeof(field))(field, def);
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		return a.readVar!T(def);
	}
}

struct HexIntegerRepresentation
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		d.writer.putValue("0x%X".format(field));
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		return a.readVar!T(def);
	}
}

/// For zero-terminated strings in fixed-length arrays.
struct CStrArrRepresentation
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		auto arr = field[];
		while (arr.length && arr[$-1] == def[arr.length-1])
			arr = arr[0..$-1];
		d.writer.putString(cast(char[])arr);
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		auto s = a.reader.readString();
		T result = def;
		enforce(s.length <= result.length, "String too long");
		foreach (i, c; s)
			result[i] = c;
		return result;
	}
}

/// Constants which are not declared as an actual enum.
struct ImplicitEnumRepresentation(members...)
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
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

	T readValue(T)(ref Assembler a, in ref T def)
	{
		auto word = a.reader.readWord();
		a.reader.endNode();

		if (word[0].isDigit())
			return parseIntLiteral!T(word);
		else
		{
			switch (word)
			{
				foreach (i, member; members)
				{
					case __traits(identifier, members[i]):
						return member;
				}
				default:
					throw new Exception("Unknown bitmask value: %s", word);
			}
		}
	}
}

/// An array which might as well be a struct with all fields of the same type.
/// Note: the array length is not represented (because entries with
/// default values are omitted), and must be fixed or specified elsewhere.
struct SparseNamedIndexedArrayRepresentation(members...)
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.writer.beginStruct();
		foreach (i, ref a; field)
		{
			auto aDef = i < def.length ? def[i] : typeof(a).init;
			if (a == aDef)
				continue;
		memberSwitch:
			switch (i)
			{
				foreach (memberIndex, member; members)
				{
					case member:
						d.writer.beginTag(__traits(identifier, members[memberIndex]));
						break memberSwitch;
				}
				default:
					d.writer.beginTag(text(i));
			}
			d.putVar!(typeof(a))(a, aDef);
			d.writer.endTag();
		}
		d.writer.endStruct();
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		a.reader.beginStruct();
		T result = def.clone();
		alias E = typeof(result[0]);
		while (!a.reader.skipEndStruct())
		{
			auto tag = a.reader.readTag();
		memberSwitch:
			switch (tag)
			{
				foreach (i, member; members)
				{
					enum name = __traits(identifier, members[i]);
					case name:
						enforce(result.length > member, "%s array too small to fit member %s".format(T.stringof, name));
						result[member] = a.readVar!E(member < def.length ? def[member] : initOf!E);
						break memberSwitch;
				}
				default:
					throw new Exception("Unknown array index constant: %s", tag);
			}
		}
		return result;
	}
}

/// Bitmask using constants which are not declared as an actual enum.
struct ImplicitEnumBitmaskRepresentation(members...)
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
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

	T readValue(T)(ref Assembler a, in ref T def)
	{
		T result;
		while (!a.reader.skipEndNode())
		{
			auto word = a.reader.readWord();
			if (word[0].isDigit())
				result |= parseIntLiteral!T(word);
			else
			{
			memberSwitch:
				switch (word)
				{
					foreach (i, member; members)
					{
						case __traits(identifier, members[i]):
							result |= member;
							break memberSwitch;
					}
					default:
						throw new Exception("Unknown bitmask value: %s".format(word));
				}
			}
		}
		return result;
	}
}

/// Unix timestamp Representation.
struct UnixTimestampRepresentation
{
	enum timeFormat = "Y-m-d H:i:s";

	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		static assert(is(F : long));
		SysTime time = SysTime.fromUnixTime(field);
		d.writer.putValue(time.formatTime!timeFormat);
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		auto dateStr = a.reader.readWord();
		auto timeStr = a.reader.readWord();
		a.reader.endNode();
		return (dateStr ~ " " ~ timeStr).parseTime!timeFormat.toUnixTime.to!T();
	}
}

/// Representation for unions. fieldIndex indicates the index of the union
/// field we will be looking at.
struct UnionRepresentation(uint fieldIndex)
{
	void putValue(F, D)(ref Disassembler d, in ref F field, in ref D def)
		if (is(typeof(field) == typeof(def)))
	{
		d.writer.beginStruct();
		foreach (i, ref f; field.tupleof)
			static if (i == fieldIndex)
			{
				enum name = __traits(identifier, field.tupleof[i]);
				d.writer.beginTag(name);
				getRepresentation!(F, name).putValue(d, f, def.tupleof[i]);
				d.writer.endTag();
			}
		d.writer.endStruct();
	}

	T readValue(T)(ref Assembler a, in ref T def)
	{
		a.reader.beginStruct();
		T result;
		foreach (i, ref f; result.tupleof)
			static if (i == fieldIndex)
			{
				a.reader.expectTag(__traits(identifier, result.tupleof[i]));
				f = a.readVar!(typeof(f))(def.tupleof[i]);
			}
		a.reader.endStruct();
		return result;
	}
}

auto getRepresentation(T, string name)()
{
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "TimeDateStamp")
		return UnixTimestampRepresentation();
	else
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "SizeOfOptionalHeader")
		return HexIntegerRepresentation();
	else
	static if (is(Unqual!T == IMAGE_FILE_HEADER) && name == "Characteristics")
		return ImplicitEnumBitmaskRepresentation!(
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
		return HexIntegerRepresentation();
	else
	static if (is(Unqual!T == IMAGE_OPTIONAL_HEADER) && name == "Subsystem")
		return ImplicitEnumRepresentation!(
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
		return ImplicitEnumBitmaskRepresentation!(
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
		return ImplicitEnumBitmaskRepresentation!(
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
		return CStrArrRepresentation();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name.isOneOf("VirtualAddress", "SizeOfRawData", "PointerToRawData"))
		return HexIntegerRepresentation();
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER) && name == "Misc")
		return UnionRepresentation!1(); // VirtualSize
	else
	static if (is(Unqual!T == IMAGE_SECTION_HEADER._Misc) && name == "VirtualSize")
		return HexIntegerRepresentation();
	else
	static if (is(Unqual!T == CLIFile.Header) && name == "dataDirectories")
		return SparseNamedIndexedArrayRepresentation!(
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
		return HexIntegerRepresentation();
	else
	static if (is(Unqual!T == CLIFile.UnaccountedBlock) && name == "offset")
		return HexIntegerRepresentation();
	else
		return DefaultRepresentation();
}
