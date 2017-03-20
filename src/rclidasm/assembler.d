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
import rclidasm.maybe;
import rclidasm.reader;
import rclidasm.representation;

T parseIntLiteral(T)(string s)
{
	alias O = OriginalType!T;
	if (s.skipOver("0x"))
		return s.to!O(16).to!T;
	else
	if (s.skipOver("0b"))
		return s.to!O(2).to!T;
	else
		return s.to!T();
}

struct Assembler
{
	this(string src)
	{
		reader = Reader(src);
	}

	Maybe!CLIFile assemble()
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

	Maybe!T readVar(T, Representation = DefaultRepresentation)()
	{
		static assert(!is(T == Maybe!U, U), "Trying to readVar a Maybe: " ~ T.stringof);
		static if (is(Representation == DefaultRepresentation))
		{
			static if (is(T == struct))
			{
				reader.beginStruct();
				Maybe!T var;
				var.isSet = true;

				while (!reader.skipEndStruct())
				{
					auto name = reader.readTag();
				structSwitch:
					switch (name)
					{
						foreach (i, f; T.init.tupleof)
						{
							alias F = typeof(T.tupleof[i]);
							enum fieldName = __traits(identifier, initOf!T.tupleof[i]);
							case fieldName:
							{
								var._maybeGetValue.tupleof[i] = readVar!(F, RepresentationOf!(T, F, fieldName))();
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
				return true.maybe;
			else
			static if (is(T : ulong))
			{
				auto value = reader.readWord().parseIntLiteral!T();
				reader.endNode();
				return value.maybe;
			}
			else
			static if (is(T : const(char[])) || is(T : const(wchar[])) || is(T : const(dchar[])))
			{
				auto value = reader.readString();
				reader.endNode();
				return value.to!T.maybe;
			}
			else
			static if (is(T U : U*))
			{
				if (reader.skipEndNode())
					return null.maybe!T;
				else
				{
					Maybe!U contents = readVar!(U, RepresentationOf!(T, U, null))();
					Maybe!T result;
					if (contents.isSet)
					{
						auto contentsPtr = [contents].ptr;
						result = contentsPtr;
					}
					else
						result = null;
					return result;
					// callee readVar will call endNode
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
				return result.maybe;
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
				Maybe!T result;
				result.isSet = true;
				foreach (i, ref f; result)
				{
					enforce(reader.readTag() == Unqual!A.stringof, "%s tag expected".format(Unqual!A.stringof));
					f = readVar!(A, RepresentationOf!(T, A, null))();
				}
				reader.endStruct();
				reader.endNode();
				return result;
			}
			else
			static if (is(T A : A[]))
			{
				reader.beginStruct();
				Maybe!T result;
				result.isSet = true;
				while (!reader.skipEndStruct())
				{
					enforce(reader.readTag() == Unqual!A.stringof, "%s tag expected".format(Unqual!A.stringof));
					result ~= readVar!(A, RepresentationOf!(T, A, null))();
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
			return readVar!T();
		}
		else
		static if (is(Representation == CStrArrRepresentation))
		{
			auto s = reader.readString();
			T result;
			enforce(s.length <= result.length, "String too long");
			foreach (i, c; s)
				result[i] = c;
			return result.maybe;
		}
		else
		static if (is(Representation == ImplicitEnumRepresentation!members, members...))
		{
			auto word = reader.readWord();
			reader.endNode();

			if (word[0].isDigit())
				return parseIntLiteral!T(word).maybe;
			else
			{
				switch (word)
				{
					foreach (i, member; members)
					{
						case __traits(identifier, members[i]):
							return member.maybe!T();
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
			Maybe!T result;
			result.isSet = true;
			alias E = typeof(T.init[0]);
			alias M = typeof(members[0]);
			while (!reader.skipEndStruct())
			{
				M index;
				auto tag = reader.readTag();
				if (tag[0].isDigit())
					index = parseIntLiteral!M(tag);
				else
				{
				memberSwitch:
					switch (tag)
					{
						foreach (i, member; members)
						{
							enum name = __traits(identifier, members[i]);
							case name:
								index = member;
								break memberSwitch;
						}
						default:
							throw new Exception("Unknown array index constant: %s".format(tag));
					}
				}

				if (result.length <= index)
					result.length = index + 1;
				result[index] = readVar!E();
				assert(isSet(result[index]));
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
			return result.maybe;
		}
		else
		static if (is(Representation == UnixTimestampRepresentation))
		{
			auto dateStr = reader.readWord();
			auto timeStr = reader.readWord();
			reader.endNode();
			return (dateStr ~ " " ~ timeStr).parseTime!(UnixTimestampRepresentation.timeFormat).toUnixTime.to!T().maybe;
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
					f = readVar!(typeof(f))();
				}
			reader.endStruct();
			return result.maybe;
		}
		else
		static if (is(Representation == PropMapRepresentation!PropMaps, PropMaps...))
		{
			reader.beginStruct();
			Maybe!T result;
			result.isSet = true;
			while (!reader.skipEndStruct())
			{
				auto tag = reader.readTag();
			memberSwitch:
				switch (tag)
				{
					foreach (RPropMap; PropMaps)
						static if (is(RPropMap == PropMap!(name, getter, setter), string name, alias getter, alias setter))
						{
							alias FM = typeof(getter(result));
							static if (is(FM == Maybe!U, U))
								alias F = U;
							else
								static assert(false, "Not a Maybe: " ~ FM.stringof);
							case name:
							{
								auto value = readVar!(F, RepresentationOf!(T, F, name))();
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
			return readVar!(T, NextRepresentation)();
		}
		else
		static if (is(Representation == SelectRepresentation!(cond, Representations), alias cond, Representations...))
		{
			switch (cond(null))
			{
				foreach (i, Representation; Representations)
				{
					case i:
						return readVar!(T, Representation)();
				}
				default:
					assert(false);
			}
		}
		else
			static assert(false, "Unknown representation: " ~ Representation.stringof);
	}
}
