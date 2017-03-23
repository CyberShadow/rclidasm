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

import rclidasm.common : DeepUnqual;

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
