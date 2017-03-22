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

module rclidasm.maybe;

import ae.utils.meta;
import ae.utils.text.ascii;

import std.format;
import std.traits;

import rclidasm.common : DeepUnqual, initOf;

/// A recursively-converting implementation of Maybe
struct Maybe(T)
{
	static assert(!is(T == Maybe!U, U), "Recursive Maybe: " ~ T.stringof);
	static assert(!is(T == Maybify!U, U), "Recursive Maybe/Maibify: " ~ T.stringof);
	static assert(is(Unqual!T == T), "Qualified Maybe: " ~ T.stringof);

	private Maybify!T _maybeValue;
	private bool _maybeIsSet;

	this(ref T value)
	{
		this = value;
	}

	void opAssign()(auto ref T value)
	{
		this._maybeValue = maybify(value);
		this._maybeIsSet = true;
	}

	static if (!is(T == Maybify!T))
	void opAssign(ref Maybify!T value)
	{
		this._maybeValue = value;
		this._maybeIsSet = true;
	}

	/*private*/ ref inout(Maybify!T) _maybeGetValue() inout @property
	{
		assert(_maybeIsSet, "This %s is not set".format(T.stringof));
		return _maybeValue;
	}

	alias _maybeGetValue this;
}

/// Is this Maybe set?
ref inout(bool) isSet(T)(ref inout(T) maybe) @property
if (is(T == Maybe!U, U))
{
	return maybe._maybeIsSet;
}

/// Map a composite type's values using func
inout(R) fmap(alias func, R, T)(ref inout(T) v)
{
	static if (is(T == struct) || is(T == union))
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

/// Get this Maybe's underlying value
inout(Unmaybify!M) value(M)(auto ref inout(M) maybe) @property
if (is(M == Maybe!U, U))
{
	alias T = Unmaybify!M;

	static if (is(T == Maybe!U, U))
		return maybe._maybeGetValue;
	else
	static if (is(Maybify!T == T))
		return maybe._maybeGetValue;
	else
		return fmap!(.value, T)(maybe._maybeGetValue);
}

/// Return the Maybe's value, with a fallback if it doesn't have one
inout(T) get(T)(auto ref inout Maybe!T m, auto ref inout(T) def)
{
	static if (is(T == struct) || is(T == union))
	{
		T result;
		auto vp = &(m._maybeGetValue());
		foreach (i, ref f; (*vp).tupleof)
		{
			auto v = get(f, def.tupleof[i]);
			result.tupleof[i] = cast(DeepUnqual!(typeof(v)))v;
		}
		return cast(inout)result;
	}
	else
		return isSet(m) ? value(m) : def;
}

/// Create and return new Maybe with this value
Maybe!T maybe(T)(auto ref T value)
{
	return Maybe!T(value);
}

enum Maybe!T nothing(T) = Maybe!T();

template Unmaybify(M)
{
	static if (is(M == Maybe!U, U))
		alias Unmaybify = U;
	else
		static assert(false, "Not a Maybe: " ~ M.stringof);
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
private template TypeMap(T, alias Tpl)
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


/// Convert a type such that all of its subtypes are replaced with Maybe!T
private template Maybify(T)
{
	static assert(is(Unqual!T == T), "Qualified Maybify: " ~ T.stringof);
	static if (is(T == Maybe!U, U))
		static assert(false, "Can't Maybify a " ~ T.stringof);
	else
	static if (is(T == struct) || is(T == union))
	{
		struct Maybify
		{
			mixin(mixTypeMapStruct!(T, q{Maybe}));

			this(ref T value)
			{
				this = value;
			}

			void opAssign(ref T value)
			{
				foreach (i, ref f; this.tupleof)
				{
					f._maybeValue = maybify(value.tupleof[i]);
					f._maybeIsSet = true;
				}
			}
		}
	}
	else
	static if (__traits(isArithmetic, T))
		alias Maybify = T;
	else
	static if (is(T AA == AA[]) && __traits(isArithmetic, AA))
		alias Maybify = AA[];
	else
		alias Maybify = TypeMap!(T, Maybe);
}

auto ref Maybify!T maybify(T)(ref T value)
{
	alias M = typeof(return);
	static if (is(T == Maybe!U, U))
		return value;
	else
	static if (is(Maybify!T == T))
		return value;
	else
	static if (is(T == struct) || is(T == union))
		return M(value);
	else
	static if (is(T U : U*))
		return value ? [maybe(*value)].ptr : null;
	else
	static if (is(T : A[n], A, size_t n))
	{
		Maybe!A[n] result;
		foreach (i, ref A a; value)
			result[i] = a;
		return result;
	}
	else
	static if (is(T A : A[]))
	{
		Maybe!A[] result = new Maybe!A[value.length];
		foreach (i, ref A a; value)
			result[i] = a;
		return result;
	}
	else
		static assert(false, "Don't know how to maybify " ~ T.stringof);
}

import core.exception : AssertError;
import std.exception : assertThrown;

unittest
{
	Maybe!int i;
	assert(!i.isSet());
	assertThrown!AssertError(i == 5);
	i = 5;
	assert(i.isSet());

	int j = i.value;
	assert(j == 5);
}

unittest
{
	static struct A
	{
		int i;
	}

	static struct B
	{
		A a;
	}

	Maybe!B b;

	assert(!b.isSet);
	assertThrown!AssertError(b.a);

	b.isSet = true;
	assertThrown!AssertError(b.a.i);
	assert(!b.a.isSet);

	b.a = A(5);
	assert(b.a.isSet);
}

unittest
{
	static union U { int a; uint b; }
	static struct S
	{
		ubyte[4] sarr;
		ubyte[] darr;
		S[] sdarr;
		S* sptr;
		U u;
	}

	Maybe!S ms;
	ms = S.init;
	S s = value(ms);
	get(ms, s);
}
