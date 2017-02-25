module rclidasm.assembler;

import ae.utils.time.parse;

import std.algorithm.searching;
import std.ascii;
import std.base64;
import std.conv;
import std.exception;
import std.string;
import std.traits;

import rclidasm.clifile;
import rclidasm.common;
import rclidasm.reader;
import rclidasm.representation;

T parseIntLiteral(T)(string s)
{
	if (s.skipOver("0x"))
		return s.to!T(16);
	else
	if (s.skipOver("0b"))
		return s.to!T(2);
	else
		return s.to!T();
}

struct Assembler
{
	this(string src)
	{
		reader = Reader(src);
	}

	CLIFile assemble()
	{
		try
		{
			reader.expectTag("file");
			return readVar!CLIFile();
		}
		catch (Exception e)
		{
			throw new Exception("Error at %d,%d".format(reader.position.tupleof), e);
		}
	}

private:
	Reader reader;

	T readVar(T, Representation = DefaultRepresentation)(in ref T def = initOf!T)
	{
		static if (is(Representation == DefaultRepresentation))
		{
			static if (is(T == struct))
			{
				reader.beginStruct();
				T var = def.clone();
				while (!reader.skipEndStruct())
				{
					auto name = reader.readTag();
				structSwitch:
					switch (name)
					{
						foreach (i, ref f; var.tupleof)
						{
							enum fieldName = __traits(identifier, var.tupleof[i]);
							case fieldName:
							{
								static assert(is(typeof(f = f)), typeof(f).stringof);
								var.tupleof[i] = readVar!(typeof(f), RepresentationOf!(T, fieldName))(def.tupleof[i]);
								break structSwitch;
							}
						}
						default:
							throw new Exception("Unknown %s field: %s".format(T.stringof, name));
					}
				}
				reader.endNode();
				return var;
			}
			else
			static if (is(T == union))
			{
				static assert(false, "Can't unserialize a union: " ~ T.stringof);
			}
			else
			static if (is(T : ulong))
			{
				auto value = reader.readWord().parseIntLiteral!T();
				reader.endNode();
				return value;
			}
			else
			static if (is(T == string))
			{
				auto value = reader.readString();
				reader.endNode();
				return value;
			}
			else
			static if (is(T : const(ubyte)[]))
			{
				reader.beginData();
				T result;
				while (!reader.skipEndData())
					result ~= Base64.decode(reader.readData());
				reader.endNode();
				return result;
			}
			else
			static if (is(T : A[n], A, size_t n))
			{
				reader.beginStruct();
				T result;
				foreach (i, ref f; result)
				{
					enforce(reader.readTag() == Unqual!A.stringof, "%s tag expected".format(Unqual!A.stringof));
					f = readVar!A(def[i]);
				}
				reader.endStruct();
				reader.endNode();
				return result;
			}
			else
			static if (is(T A : A[]))
			{
				reader.beginStruct();
				T result;
				while (!reader.skipEndStruct())
				{
					enforce(reader.readTag() == Unqual!A.stringof, "%s tag expected".format(Unqual!A.stringof));
					const A aDef = result.length < def.length ? def[result.length] : A.init;
					result ~= readVar!A(aDef);
				}
				reader.endNode();
				return result;
			}
			else
				static assert(false, "Don't know how to put " ~ T.stringof);
		}
		else
		static if (is(Representation == HexIntegerRepresentation))
		{
			return readVar!T(def);
		}
		else
		static if (is(Representation == CStrArrRepresentation))
		{
			auto s = reader.readString();
			T result = def;
			enforce(s.length <= result.length, "String too long");
			foreach (i, c; s)
				result[i] = c;
			return result;
		}
		else
		static if (is(Representation == ImplicitEnumRepresentation!members, members...))
		{
			auto word = reader.readWord();
			reader.endNode();

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
		else
		static if (is(Representation == SparseNamedIndexedArrayRepresentation!members, members...))
		{
			reader.beginStruct();
			T result = def.clone();
			alias E = typeof(result[0]);
			while (!reader.skipEndStruct())
			{
				auto tag = reader.readTag();
			memberSwitch:
				switch (tag)
				{
					foreach (i, member; members)
					{
						enum name = __traits(identifier, members[i]);
						case name:
							enforce(result.length > member, "%s array too small to fit member %s".format(T.stringof, name));
							result[member] = readVar!E(member < def.length ? def[member] : initOf!E);
							break memberSwitch;
					}
					default:
						throw new Exception("Unknown array index constant: %s", tag);
				}
			}
			return result;
		}
		else
		static if (is(Representation == ImplicitEnumBitmaskRepresentation!members, members...))
		{
			T result;
			while (!reader.skipEndNode())
			{
				auto word = reader.readWord();
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
		else
		static if (is(Representation == UnixTimestampRepresentation))
		{
			auto dateStr = reader.readWord();
			auto timeStr = reader.readWord();
			reader.endNode();
			return (dateStr ~ " " ~ timeStr).parseTime!(UnixTimestampRepresentation.timeFormat).toUnixTime.to!T();
		}
		else
		static if (is(Representation == UnionRepresentation!fieldIndex, uint fieldIndex))
		{
			reader.beginStruct();
			T result;
			foreach (i, ref f; result.tupleof)
				static if (i == fieldIndex)
				{
					reader.expectTag(__traits(identifier, result.tupleof[i]));
					f = readVar!(typeof(f))(def.tupleof[i]);
				}
			reader.endStruct();
			return result;
		}
		else
			static assert(false, "Unknown representation: " ~ Representation.stringof);
	}
}
