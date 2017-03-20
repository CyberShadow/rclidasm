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

module rclidasm.disassembler;

import ae.utils.time.format;

import std.conv;
import std.datetime;
import std.string;
import std.traits;

import rclidasm.common;
import rclidasm.clifile;
import rclidasm.maybe;
import rclidasm.representation;
import rclidasm.writer;

struct Disassembler
{
	string disassemble()
	{
		writer.beginTag("file");
		putVar(*file);
		writer.endTag();
		return writer.data;
	}

private:
	Maybe!CLIFile* file;

	Writer writer;

	void putVar(M, Representation = DefaultRepresentation)(ref M var)
	{
		alias T = Unmaybify!M;
		static if (is(Representation == DefaultRepresentation))
		{
			static if (is(T == struct))
			{
				writer.beginStruct();
				foreach (i, ref f; var._maybeGetValue.tupleof)
				{
					if (!isSet(f))
						continue;

					enum name = __traits(identifier, T.tupleof[i]);
					writer.beginTag(name);
					putVar!(typeof(f), RepresentationOf!(T, Unmaybify!(typeof(f)), name))(f);
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
			static if (is(T == bool))
			{} // presence indicates 'true'
			else
			static if (is(T : ulong))
			{
				writer.putValue(text(var)); // TODO: Don't allocate
			}
			else
			static if (is(T : const(char[])) || is(T : const(wchar[])) || is(T : const(dchar[])))
			{
				writer.putString(var.get(null).to!string);
			}
			else
			static if (is(T U : U*))
			{
				if (var)
					putVar!(Maybe!U, RepresentationOf!(T, U, null))(*var);
			}
			else
			static if (is(T : const(ubyte)[]))
				writer.putData(var);
			else
			static if (is(const(T) == const(void[])))
				writer.putData(cast(const(ubyte)[])var);
			else
			static if (is(T A : A[]))
			{
				writer.beginStruct();
				foreach (i, ref Maybe!A a; var)
				{
					writer.beginTag(Unqual!A.stringof);
					if (isSet(a))
						putVar!(Maybe!A, RepresentationOf!(T, A, null))(a);
					writer.endTag();
				}
				writer.endStruct();
			}
			else
				static assert(false, "Don't know how to put " ~ T.stringof);
		}
		else
		static if (is(Representation == HexIntegerRepresentation))
		{
			static assert(is(T : long));
			writer.putValue("0x%X".format(var));
		}
		else
		static if (is(Representation == CStrArrRepresentation))
		{
			auto arr = var[];
			while (arr.length && !arr[$-1].isSet)
				arr = arr[0..$-1];
			char[var.length] s;
			foreach (i, c; arr)
				s[i] = c.get(typeof(c.value).init);
			writer.putString(s);
		}
		else
		static if (is(Representation == ImplicitEnumRepresentation!members, members...))
		{
			static assert(is(T : long));
			switch (var)
			{
				foreach (i, member; members)
				{
					case member:
						writer.putValue(__traits(identifier, members[i]));
						return;
				}
				default:
					writer.putValue("%d".format(var));
			}
		}
		else
		static if (is(Representation == SparseNamedIndexedArrayRepresentation!members, members...))
		{
			writer.beginStruct();
			foreach (i, ref a; var)
			{
				if (!isSet(a))
					continue;
			memberSwitch:
				switch (i)
				{
					foreach (memberIndex, member; members)
					{
						case member:
							writer.beginTag(__traits(identifier, members[memberIndex]));
							break memberSwitch;
					}
					default:
						writer.beginTag(text(i));
				}
				putVar!(typeof(a))(a);
				writer.endTag();
			}
			writer.endStruct();
		}
		else
		static if (is(Representation == ImplicitEnumBitmaskRepresentation!members, members...))
		{
			static assert(is(T : long));
			Unqual!T remainingBits = var;
			foreach (i, member; members)
				if ((remainingBits & member) == member)
				{
					writer.putValue(__traits(identifier, members[i]));
					remainingBits &= ~member;
				}
			for (Unqual!T mask = 1; mask; mask <<= 1)
				if (remainingBits & mask)
					writer.putValue("0x%x".format(mask));
		}
		else
		static if (is(Representation == UnixTimestampRepresentation))
		{
			static assert(is(T : long));
			SysTime time = SysTime.fromUnixTime(var);
			writer.putValue(time.formatTime!(UnixTimestampRepresentation.timeFormat));
		}
		else
		static if (is(Representation == UnionRepresentation!fieldIndex, uint fieldIndex))
		{
			writer.beginStruct();
			foreach (i, ref f; var._maybeGetValue.tupleof)
				static if (i == fieldIndex)
				{
					enum name = __traits(identifier, typeof(var._maybeGetValue).tupleof[i]);
					writer.beginTag(name);
					putVar!(typeof(f), RepresentationOf!(T, Unmaybify!(typeof(f)), name))(f);
					writer.endTag();
				}
			writer.endStruct();
		}
		else
		static if (is(Representation == PropMapRepresentation!PropMaps, PropMaps...))
		{
			writer.beginStruct();
			foreach (RPropMap; PropMaps)
				static if (is(RPropMap == PropMap!(name, getter, setter), string name, alias getter, alias setter))
				{
					alias F = typeof(getter(var));
					auto f = getter(var);
					if (isSet(f))
					{
						writer.beginTag(name);
						putVar!(F, RepresentationOf!(T, Unmaybify!F, name))(f);
						writer.endTag();
					}
				}
				else
					static assert(false);
			writer.endStruct();
		}
		else
		static if (is(Representation == ContextRepresentation!(beforeWrite, afterWrite, NextRepresentation), alias beforeWrite, alias afterWrite, NextRepresentation))
		{
			beforeWrite(var);
			scope(exit) afterWrite(var);
			putVar!(M, NextRepresentation)(var);
		}
		else
		static if (is(Representation == SelectRepresentation!(cond, Representations), alias cond, Representations...))
		{
		selectSwitch:
			switch (cond(&var))
			{
				foreach (i, Representation; Representations)
				{
					case i:
						putVar!(M, Representation)(var);
						break selectSwitch;
				}
				default:
					assert(false);
			}
		}
		else
			static assert(false, "Unknown representation: " ~ Representation.stringof);
	}
}
