module rclidasm.disassembler;

import std.conv;
import std.traits;

import rclidasm.common;
import rclidasm.clifile;
import rclidasm.serialization;
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

	public/*!*/ Writer writer;

	public/*!*/ void putVar(T)(ref T var, in ref T def = initOf!T)
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
				getRepresentation!(T, name).putValue(this, f, def.tupleof[i]);
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
