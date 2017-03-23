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

module rclidasm.meta;

import std.traits;

import ae.utils.meta : RangeTuple;
import ae.utils.text.ascii : toDec;

template DeepUnqual(T)
{
	static if (is(T A == A[]))
		alias DeepUnqual = Unqual!A[];
	else
	static if (is(T U == U*))
		alias DeepUnqual = Unqual!U*;
	else
		alias DeepUnqual = Unqual!T;
}

enum mixTypeMapStruct(T, string tplName) = {
	string s;
	foreach (i; RangeTuple!(T.init.tupleof.length))
	{
		enum name = __traits(identifier, T.tupleof[i]);
		s ~= tplName ~ "!(typeof({ T* value; return (*value).tupleof[" ~ toDec(i) ~ "]; }())) " ~ name ~ ";\n";
	}
	return s;
}();

/// Convert a composite type such that all of its direct subtypes are replaced with Tpl!T
template TypeMap(T, alias Tpl)
{
	static assert(is(Unqual!T == T), "Qualified TypeMap: " ~ T.stringof); // Watch me
	static if (is(T == Tpl!U, U))
		static assert(false, "Recursive TypeMap of " ~ T.stringof); // Almost always a mistake
	else
	static if (is(T == struct))
		struct TypeMap { mixin(mixTypeMapStruct!(T, q{Tpl})); }
	else
	static if (is(T U : U*))
		alias TypeMap = Tpl!U*;
	else
	static if (is(T : A[n], A, size_t n))
		alias TypeMap = Tpl!A[n];
	else
	static if (is(T A : A[]))
		alias TypeMap = Tpl!A[];
	else
		static assert(false, "Don't know how to TypeMap " ~ T.stringof);
}

/// Map a composite type's values using func
inout(R) fmap(alias func, R, T)(ref inout(T) v)
{
	static if (is(T == struct))
	{
		R result;
		foreach (i, ref f; v.tupleof)
			result.tupleof[i] = cast(DeepUnqual!(typeof(func(f))))func(f);
		return cast(inout)result;
	}
	else
	static if (is(T U : U*))
		return v ? [func(*v)].ptr : null;
	else
	static if (is(T : A[n], A, size_t n))
	{
		R result;
		foreach (i, ref inout(A) a; v)
			result[i] = cast()func(a);
		return result;
	}
	else
	static if (is(T A : A[]))
	{
		alias E = typeof(R.init[0]);
		R result = new E[v.length];
		foreach (i, ref inout(A) a; v)
			result[i] = cast(DeepUnqual!(typeof(func(a))))func(a);
		return cast(inout)result;
	}
	else
		static assert(false, "Don't know how to fmap " ~ T.stringof ~ " (to " ~ R.stringof ~ ")");
}

/// Wrap a template instantiation into a struct,
/// to allow recursive template instantiations.
struct StructWrap(alias Tpl, T)
{
	Tpl!T field;
}

template EnforceNoUnionsImpl(T)
{
	static if (is(T == union))
		static assert(false, T.stringof ~ " is a union");
	else
	static if (is(T == struct))
	{
		bool testUnions()
		{
			foreach (i, f; T.init.tupleof)
				static assert(!i || T.tupleof[i].offsetof > T.tupleof[i-1].offsetof, "Inline union detected in " ~ T.stringof);
			return true;
		}
		static assert(testUnions()); // Force evaluation
		alias EnforceNoUnionsImpl = TypeMap!(T, .EnforceNoUnions);
	}
	else
	static if (isNumeric!T)
		alias EnforceNoUnionsImpl = T;
	else
		alias EnforceNoUnionsImpl = TypeMap!(T, .EnforceNoUnions);
}

alias EnforceNoUnions(T) = StructWrap!(EnforceNoUnionsImpl, T);

unittest
{
	struct S { int[] arr; }
	static assert(is(EnforceNoUnions!S));
}

unittest
{
	struct S { int a, b; }
	static assert(is(EnforceNoUnions!S));
}

unittest
{
	struct S { S[] arr; }
	static assert(is(EnforceNoUnions!S));
}

unittest
{
	union S { int a, b; }
	static assert(!is(EnforceNoUnions!S));
}

unittest
{
	struct S { int a, b; union { int c, d; } }
	static assert(!is(EnforceNoUnions!S));
}

unittest
{
	struct A { struct { int a, b; } }
	struct B { A* a; }
	struct C { B[] b; }
	struct D { C[2] c; }
	struct E { D d; }
	static assert(is(EnforceNoUnions!D));
}

unittest
{
	struct A { union { int a, b; } }
	struct B { A* a; }
	struct C { B[] b; }
	struct D { C[2] c; }
	struct E { D d; }
	static assert(!is(EnforceNoUnions!D));
}
