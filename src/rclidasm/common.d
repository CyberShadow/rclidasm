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

module rclidasm.common;

import std.ascii;
import std.traits;

import ae.utils.array;

bool isTagChar(char c)
{
	return isAlphaNum(c) || c.isOneOf("._");
}

static immutable initOf(T) = T.init;

private template DeepUnqual(T)
{
	static if (is(T A : A[]))
		alias DeepUnqual = Unqual!A[];
	else
		alias DeepUnqual = Unqual!T;
}

DeepUnqual!T clone(T)(ref T var)
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
