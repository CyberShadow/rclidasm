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
							alias F = typeof(f);
							enum fieldName = __traits(identifier, var.tupleof[i]);
							case fieldName:
							{
								static assert(is(typeof(f = f)), F.stringof);
								var.tupleof[i] = readVar!(F, RepresentationOf!(T, F, fieldName))(def.tupleof[i]);
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
			static if (is(T == bool))
				return true;
			else
			static if (is(T : ulong))
			{
				auto value = reader.readWord().parseIntLiteral!T();
				reader.endNode();
				return value;
			}
			else
			static if (is(T : const(char[])) || is(T : const(wchar[])) || is(T : const(dchar[])))
			{
				auto value = reader.readString();
				reader.endNode();
				return value.to!T;
			}
			else
			static if (is(T U : U*))
			{
				if (reader.skipEndNode())
					return null;
				else
				{
					auto result = [readVar!(U, RepresentationOf!(T, U, null))(def ? *def : initOf!U)].ptr;
					// callee readVar will call endNode
					return result;
				}
			}
			else
			static if (is(T : const(wchar)[]))
			{
				auto value = reader.readString().to!T;
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
			static if (is(const(T) == const(void[])))
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
					f = readVar!(A, RepresentationOf!(T, A, null))(def[i]);
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
					result ~= readVar!(A, RepresentationOf!(T, A, null))(aDef);
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
		static if (is(Representation == PropMapRepresentation!PropMaps, PropMaps...))
		{
			reader.beginStruct();
			T result = def.clone();
			while (!reader.skipEndStruct())
			{
				auto tag = reader.readTag();
			memberSwitch:
				switch (tag)
				{
					foreach (RPropMap; PropMaps)
						static if (is(RPropMap == PropMap!(name, toInclude, getter, setter), string name, alias toInclude, alias getter, alias setter))
						{
							alias F = typeof(clone(initOf!(typeof(getter(result)))));
							case name:
							{
								auto d = getter(def);
								auto value = readVar!(F, RepresentationOf!(T, F, name))(d);
								setter(result, value);
								break memberSwitch;
							}
						}
						else
							static assert(false);
					default:
						throw new Exception("Unknown array index constant: %s", tag);
				}
			}
			return result;
		}
		else
		static if (is(Representation == ContextRepresentation!(enter, exit, NextRepresentation), alias enter, alias exit, NextRepresentation))
		{
			return readVar!(T, NextRepresentation)(def);
		}
		else
		static if (is(Representation == SelectRepresentation!(cond, Representations), alias cond, Representations...))
		{
			switch (cond(null))
			{
				foreach (i, Representation; Representations)
				{
					case i:
						return readVar!(T, Representation)(def);
				}
				default:
					assert(false);
			}
		}
		else
			static assert(false, "Unknown representation: " ~ Representation.stringof);
	}
}
