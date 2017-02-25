module common;

import std.ascii;

import ae.utils.array;

bool isTagChar(char c)
{
	return isAlphaNum(c) || c.isOneOf("._");
}

