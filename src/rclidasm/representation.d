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

module rclidasm.representation;

import std.conv;
import std.datetime;
import std.exception;
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
import rclidasm.maybe;
import rclidasm.resources;
import rclidasm.versioninfo;

// From winver
struct VS_FIXEDFILEINFO
{
	DWORD dwSignature = 0xFEEF04BD;
	DWORD dwStrucVersion;
	DWORD dwFileVersionMS;
	DWORD dwFileVersionLS;
	DWORD dwProductVersionMS;
	DWORD dwProductVersionLS;
	DWORD dwFileFlagsMask;
	DWORD dwFileFlags;
	DWORD dwFileOS;
	DWORD dwFileType;
	DWORD dwFileSubtype;
	DWORD dwFileDateMS;
	DWORD dwFileDateLS;
}

enum VS_FF
{
	VS_FF_DEBUG        =  1,
	VS_FF_PRERELEASE   =  2,
	VS_FF_PATCHED      =  4,
	VS_FF_PRIVATEBUILD =  8,
	VS_FF_INFOINFERRED = 16,
	VS_FF_SPECIALBUILD = 32
}

enum VOS
{
	VOS_UNKNOWN       =       0,
	VOS_DOS           = 0x10000,
	VOS_OS216         = 0x20000,
	VOS_OS232         = 0x30000,
	VOS_NT            = 0x40000,
//	VOS__BASE         =       0,
	VOS__WINDOWS16    =       1,
	VOS__PM16         =       2,
	VOS__PM32         =       3,
	VOS__WINDOWS32    =       4,
	VOS_DOS_WINDOWS16 = 0x10001,
	VOS_DOS_WINDOWS32 = 0x10004,
	VOS_OS216_PM16    = 0x20002,
	VOS_OS232_PM32    = 0x30003,
	VOS_NT_WINDOWS32  = 0x40004
}

enum VFT
{
	VFT_UNKNOWN    = 0,
	VFT_APP        = 1,
	VFT_DLL        = 2,
	VFT_DRV        = 3,
	VFT_FONT       = 4,
	VFT_VXD        = 5,
	VFT_STATIC_LIB = 7
}

enum LangID : ubyte
{
	LANG_NEUTRAL,
	LANG_ARABIC,
	LANG_BULGARIAN,
	LANG_CATALAN,
	LANG_CHINESE,
	LANG_CZECH,
	LANG_DANISH,
	LANG_GERMAN,
	LANG_GREEK,
	LANG_ENGLISH,
	LANG_SPANISH,
	LANG_FINNISH,
	LANG_FRENCH,
	LANG_HEBREW,
	LANG_HUNGARIAN,
	LANG_ICELANDIC,
	LANG_ITALIAN,
	LANG_JAPANESE,
	LANG_KOREAN,
	LANG_DUTCH,
	LANG_NORWEGIAN,
	LANG_POLISH,
	LANG_PORTUGUESE,    // = 0x16
	LANG_ROMANIAN          = 0x18,
	LANG_RUSSIAN,
	LANG_CROATIAN,      // = 0x1A
//	LANG_SERBIAN           = 0x1A,
	LANG_BOSNIAN           = 0x1A,
	LANG_SLOVAK,
	LANG_ALBANIAN,
	LANG_SWEDISH,
	LANG_THAI,
	LANG_TURKISH,
	LANG_URDU,
	LANG_INDONESIAN,
	LANG_UKRAINIAN,
	LANG_BELARUSIAN,
	LANG_SLOVENIAN,
	LANG_ESTONIAN,
	LANG_LATVIAN,
	LANG_LITHUANIAN,    // = 0x27
//	LANG_FARSI             = 0x29,
	LANG_PERSIAN           = 0x29,
	LANG_VIETNAMESE,
	LANG_ARMENIAN,
	LANG_AZERI,
	LANG_BASQUE,
	LANG_LOWER_SORBIAN, // = 0x2E
	LANG_UPPER_SORBIAN     = 0x2E,
	LANG_MACEDONIAN,    // = 0x2F
	LANG_TSWANA            = 0x32,
	LANG_XHOSA             = 0x34,
	LANG_ZULU,
	LANG_AFRIKAANS,
	LANG_GEORGIAN,
	LANG_FAEROESE,
	LANG_HINDI,
	LANG_MALTESE,
	LANG_SAMI,
	LANG_IRISH,         // = 0x3C
	LANG_MALAY             = 0x3E,
	LANG_KAZAK,
	LANG_KYRGYZ,
	LANG_SWAHILI,       // = 0x41
	LANG_UZBEK             = 0x43,
	LANG_TATAR,
	LANG_BENGALI,
	LANG_PUNJABI,
	LANG_GUJARATI,
	LANG_ORIYA,
	LANG_TAMIL,
	LANG_TELUGU,
	LANG_KANNADA,
	LANG_MALAYALAM,
	LANG_ASSAMESE,
	LANG_MARATHI,
	LANG_SANSKRIT,
	LANG_MONGOLIAN,
	LANG_TIBETAN,
	LANG_WELSH,
	LANG_KHMER,
	LANG_LAO,           // = 0x54
	LANG_GALICIAN          = 0x56,
	LANG_KONKANI,
	LANG_MANIPURI,
	LANG_SINDHI,
	LANG_SYRIAC,
	LANG_SINHALESE,     // = 0x5B
	LANG_INUKTITUT         = 0x5D,
	LANG_AMHARIC,
	LANG_TAMAZIGHT,
	LANG_KASHMIRI,
	LANG_NEPALI,
	LANG_FRISIAN,
	LANG_PASHTO,
	LANG_FILIPINO,
	LANG_DIVEHI,        // = 0x65
	LANG_HAUSA             = 0x68,
	LANG_YORUBA            = 0x6A,
	LANG_QUECHUA,
	LANG_SOTHO,
	LANG_BASHKIR,
	LANG_LUXEMBOURGISH,
	LANG_GREENLANDIC,
	LANG_IGBO,          // = 0x70
	LANG_TIGRIGNA          = 0x73,
	LANG_YI                = 0x78,
	LANG_MAPUDUNGUN        = 0x7A,
	LANG_MOHAWK            = 0x7C,
	LANG_BRETON            = 0x7E,
	LANG_UIGHUR            = 0x80,
	LANG_MAORI,
	LANG_OCCITAN,
	LANG_CORSICAN,
	LANG_ALSATIAN,
	LANG_YAKUT,
	LANG_KICHE,
	LANG_KINYARWANDA,
	LANG_WOLOF,         // = 0x88
	LANG_DARI              = 0x8C,
	LANG_MALAGASY,      // = 0x8D

	LANG_INVARIANT         = 0x7F
}

struct VersionInfoTranslation
{
	LangID langID;
	ubyte sublangID;
	ushort charsetID;
}

struct DefaultRepresentation {}

struct HexIntegerRepresentation {}

/// For zero-terminated strings in fixed-length arrays.
struct CStrArrRepresentation {}

/// Constants which are not declared as an actual enum.
struct ImplicitEnumRepresentation(members...) {}

/// An actual enum.
alias EnumRepresentation(Enum) = ImplicitEnumRepresentation!(EnumMembers!Enum);

/// An array which might as well be a struct with all fields of the same type.
/// Note: the array length is not represented (because entries with
/// default values are omitted), and must be fixed or specified elsewhere.
struct SparseNamedIndexedArrayRepresentation(members...) {}

/// Bitmask using constants which are not declared as an actual enum.
struct ImplicitEnumBitmaskRepresentation(members...) {}

/// Bitmask using an actual enum.
alias EnumBitmaskRepresentation(Enum) = ImplicitEnumBitmaskRepresentation!(EnumMembers!Enum);

/// Unix timestamp Representation.
struct UnixTimestampRepresentation
{
	enum timeFormat = "Y-m-d H:i:s";
}

/// Representation for unions. fieldIndex indicates the index of the union
/// field we will be looking at.
struct UnionRepresentation(uint fieldIndex) {}

struct PropMap(string name, alias getter, alias setter) {}

/// Serialized like a struct, but with getters/setters.
struct PropMapRepresentation(PropMaps...) {}

/// Serialized like a struct, but with getters/setters.
struct ContextRepresentation(alias beforeWrite, alias afterWrite, NextRepresentation = DefaultRepresentation) {}

/// Choose a representation based on a condition.
/// cond gets called with a pointer to the field (null when reading) and must return an index.
struct SelectRepresentation(alias cond, Representations...) {}

int[] resourceStack;

template RepresentationOf(P, F, string name)
{
	alias M = Maybe;
	alias MF = Maybe!(Unqual!F);

	/// Set discriminated union selector
	static void setDUS(T)(ref Maybe!T selector, T newValue)
	{
		enforce(!selector.isSet || value(selector) == newValue, "Redundant or conflicting discriminated union field");
		selector = newValue;
	}

	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "TimeDateStamp")
		alias RepresentationOf = UnixTimestampRepresentation;
	else
	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "SizeOfOptionalHeader")
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_FILE_HEADER) && name == "Characteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
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
		);
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name.isOneOf("SizeOfCode", "SizeOfInitializedData",
			"AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase", "SectionAlignment", "SizeOfImage", "SizeOfHeaders"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name == "Subsystem")
		alias RepresentationOf = ImplicitEnumRepresentation!(
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
		);
	else
	static if (is(Unqual!P == IMAGE_OPTIONAL_HEADER) && name == "DllCharacteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
			IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE,
			IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY,
			IMAGE_DLL_CHARACTERISTICS_NX_COMPAT,
			IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
			IMAGE_DLLCHARACTERISTICS_NO_SEH	,
			IMAGE_DLLCHARACTERISTICS_NO_BIND,
			IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
			IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
		);
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Characteristics")
		alias RepresentationOf = ImplicitEnumBitmaskRepresentation!(
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
		);
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Name")
		alias RepresentationOf = CStrArrRepresentation;
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name.isOneOf("VirtualAddress", "SizeOfRawData", "PointerToRawData"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER) && name == "Misc")
		alias RepresentationOf = UnionRepresentation!1; // VirtualSize
	else
	static if (is(Unqual!P == IMAGE_SECTION_HEADER._Misc) && name == "VirtualSize")
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == CLIFile.Header) && name == "dataDirectories")
		alias RepresentationOf = SparseNamedIndexedArrayRepresentation!(
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
		);
	else
	static if (is(Unqual!P == IMAGE_DATA_DIRECTORY) && name.isOneOf("VirtualAddress", "Size"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == CLIFile.UnaccountedBlock) && name == "offset")
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!F == ResourceDirectoryEntry))
		alias RepresentationOf = ContextRepresentation!(
			(in ref M!F f) { resourceStack ~= f.Id.get(0); },
			(in ref M!F f) { resourceStack = resourceStack[0..$-1]; },
			PropMapRepresentation!(
				PropMap!("NameIsString", (ref MF f) => f.NameIsString, (ref M!(Unqual!F) f,     M!(bool             ) value) { setDUS(f.NameIsString   , value);                         }),
				PropMap!("Name"        , (ref MF f) => f.Name        , (ref M!(Unqual!F) f,     M!(WCHAR[]          ) value) { setDUS(f.NameIsString   , true ); f.Name         = value; }),
				PropMap!("NameOffset"  , (ref MF f) => f.NameOffset  , (ref M!(Unqual!F) f,     M!(DWORD            ) value) { setDUS(f.NameIsString   , true ); f.NameOffset   = value; }),
				PropMap!("Id"          , (ref MF f) => f.Id          , (ref M!(Unqual!F) f,     M!(DWORD            ) value) { setDUS(f.NameIsString   , false); f.Id           = value; }),
				PropMap!("OffsetToData", (ref MF f) => f.OffsetToData, (ref M!(Unqual!F) f,     M!(DWORD            ) value) {                                   f.OffsetToData = value; }),
				PropMap!("directory"   , (ref MF f) => f.directory   , (ref M!(Unqual!F) f, ref M!(ResourceDirectory) value) { setDUS(f.DataIsDirectory, true ); f.directory    = value; }),
				PropMap!("data"        , (ref MF f) => f.data        , (ref M!(Unqual!F) f, ref M!(ResourceDataEntry) value) { setDUS(f.DataIsDirectory, false); f.data         = value; }),
		));
	else
	static if (is(Unqual!P == ResourceDirectoryEntry) && name == "Id")
		alias RepresentationOf = SelectRepresentation!(
			(in MF* f) => resourceStack.length > 1 ? 0 : 1,
			DefaultRepresentation,
			EnumRepresentation!ResourceType,
		);
	else
	static if (is(Unqual!F == VersionInfoNode))
	{
		enum Type { bin, str, trn, ver }

		static Type getType(in ref Maybe!VersionInfoNode f)
		{
			// TODO: are these .gets really necessary?
			auto type = f.type.get(0);
			auto value = f.value.get(null);

			if (type == 1 && value.length >= 2 && value.length % 2 == 0 && value[$-1] == 0 && value[$-2] == 0)
				return Type.str;
			else
			if (type == 0 && f.key == "VS_VERSION_INFO" && value.length == VS_FIXEDFILEINFO.sizeof && (cast(VS_FIXEDFILEINFO*)value.ptr).dwSignature == VS_FIXEDFILEINFO.init.dwSignature)
				return Type.ver;
			else
			if (type == 0 && f.key == "Translation" && value.length == VersionInfoTranslation.sizeof)
				return Type.trn;
			else
				return Type.bin;
		}

		alias Ver = VS_FIXEDFILEINFO;
		alias Trn = VersionInfoTranslation;

		alias RepresentationOf = PropMapRepresentation!(
			PropMap!("key"          , (ref MF f) => f.key                                                                                          , (ref M!(Unqual!F) f,     M!(wchar          []) value) { f.key      = value                     ; }),
			PropMap!("type"         , (ref MF f) => f.type                                                                                         , (ref M!(Unqual!F) f,     M!(ushort           ) value) { f.type     = value                     ; }),
			PropMap!("data"         , (ref MF f) => getType(f) == Type.bin ? f.value                                     : nothing!(const(ubyte)[]), (ref M!(Unqual!F) f,     M!(const(ubyte)   []) value) { f.value    = value.value               ; }),
			PropMap!("text"         , (ref MF f) => getType(f) == Type.str ? maybe((cast(wchar[])f.value.value)[0..$-1]) : nothing!(wchar       []), (ref M!(Unqual!F) f,     M!(wchar          []) value) { f.value    = (value.value ~ '\0').bytes; }),
			PropMap!("fixedFileInfo", (ref MF f) => getType(f) == Type.ver ? maybe((cast(Ver[])f.value.value)[0])        : nothing!(Ver           ), (ref M!(Unqual!F) f, ref M!(Ver              ) value) { f.value    = [value.get(initOf!Ver)][0].bytes.dup; }),
			PropMap!("translation"  , (ref MF f) => getType(f) == Type.trn ? maybe((cast(Trn[])f.value.value)[0])        : nothing!(Trn           ), (ref M!(Unqual!F) f, ref M!(Trn              ) value) { f.value    = [value.get(initOf!Trn)][0].bytes.dup; }),
			PropMap!("children"     , (ref MF f) => f.children                                                                                     , (ref M!(Unqual!F) f,     M!(VersionInfoNode[]) value) { f.children = value                     ; }),
		);
	}
	else
	static if (is(Unqual!P == VS_FIXEDFILEINFO) && name.isOneOf("dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS", "dwProductVersionMS", "dwProductVersionLS"))
		alias RepresentationOf = HexIntegerRepresentation;
	else
	static if (is(Unqual!P == VS_FIXEDFILEINFO) && name.isOneOf("dwFileFlagsMask", "dwFileFlags"))
		alias RepresentationOf = EnumBitmaskRepresentation!VS_FF;
	else
	static if (is(Unqual!P == VS_FIXEDFILEINFO) && name == "dwFileOS")
		alias RepresentationOf = EnumRepresentation!VOS;
	else
	static if (is(Unqual!P == VS_FIXEDFILEINFO) && name == "dwFileType")
		alias RepresentationOf = EnumRepresentation!VFT;
	else
	static if (is(Unqual!P == CLIFile.Fixup) && name == "rva")
		alias RepresentationOf = HexIntegerRepresentation;
	else
		alias RepresentationOf = DefaultRepresentation;
}
