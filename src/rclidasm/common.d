module rclidasm.common;

import std.ascii;
import std.traits;

import ae.utils.array;

bool isTagChar(char c)
{
	return isAlphaNum(c) || c.isOneOf("._");
}

static immutable initOf(T) = T.init;

auto clone(T)(ref T var)
{
	static if (!hasIndirections!T)
	{
		Unqual!T result = var;
		return result;
	}
	else
	static if (is(T == struct))
	{
		Unqual!T result;
		foreach (i, ref f; var.tupleof)
			result.tupleof[i] = var.tupleof[i].clone();
		return result;
	}
	else
	static if (isDynamicArray!T)
	{
		alias E = Unqual!(typeof(var[0]));
		E[] result = new E[var.length];
		foreach (i, ref f; var)
			result[i] = f.clone();
		return result;
	}
	else
		static assert(false, "Don't know how to clone " ~ T.stringof);
}
