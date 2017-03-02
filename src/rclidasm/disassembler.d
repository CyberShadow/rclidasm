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
	const(CLIFile)* file;

	Writer writer;

	void putVar(T, Representation = DefaultRepresentation)(ref T var, in ref T def = initOf!T)
	{
		static if (is(Representation == DefaultRepresentation))
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
					putVar!(typeof(f), RepresentationOf!(T, typeof(f), name))(f, def.tupleof[i]);
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
				writer.putString(var.to!string);
			}
			else
			static if (is(T U : U*))
			{
				if (var)
					putVar!(U, RepresentationOf!(T, U, null))(*var, def ? *def : initOf!U);
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
				foreach (i, ref A a; var)
				{
					writer.beginTag(Unqual!A.stringof);
					auto aDef = i < def.length ? def[i] : A.init;
					if (a != aDef)
						putVar!(A, RepresentationOf!(T, A, null))(a, aDef);
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
			while (arr.length && arr[$-1] == def[arr.length-1])
				arr = arr[0..$-1];
			writer.putString(cast(char[])arr);
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
				auto aDef = i < def.length ? def[i] : typeof(a).init;
				if (a == aDef)
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
				putVar!(typeof(a))(a, aDef);
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
			foreach (i, ref f; var.tupleof)
				static if (i == fieldIndex)
				{
					enum name = __traits(identifier, var.tupleof[i]);
					writer.beginTag(name);
					putVar!(typeof(f), RepresentationOf!(T, typeof(f), name))(f, def.tupleof[i]);
					writer.endTag();
				}
			writer.endStruct();
		}
		else
		static if (is(Representation == PropMapRepresentation!PropMaps, PropMaps...))
		{
			writer.beginStruct();
			foreach (RPropMap; PropMaps)
				static if (is(RPropMap == PropMap!(name, toInclude, getter, setter), string name, alias toInclude, alias getter, alias setter))
				{
					if (!toInclude(var))
						continue;
					alias F = typeof(getter(var));
					auto f = getter(var);
					auto d = getter(def);
					if (f != d)
					{
						writer.beginTag(name);
						putVar!(F, RepresentationOf!(T, F, name))(f, d);
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
			putVar!(T, NextRepresentation)(var, def);
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
						putVar!(T, Representation)(var, def);
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
