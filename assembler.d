module assembler;

import std.base64;
import std.exception;
import std.string;
import std.traits;

import clifile;
import common;
import reader;
import serialization;

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
	public/*!*/ Reader reader;

	T readVar(T)(in ref T def = initOf!T)
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
							var.tupleof[i] = getSerializer!(T, fieldName).readValue!(typeof(f))(this, def.tupleof[i]);
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
}
