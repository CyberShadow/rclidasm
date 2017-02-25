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

module rclidasm.tokenizer;

import std.exception;

import rclidasm.common;

/// SDLang tokenizer.
struct Tokenizer
{
	@disable this();
	@disable this(this);

	struct Token
	{
		enum Type
		{
			word,               // Tag name, number, enum value, data block
			beginStruct,        // {
			endStruct,          // }
			nodeDelim,          // Newline or ;
			string,             // Quoted string
			beginData,          // [
			endData,            // ]
			eof,
		}
		Type type;

		string value;           // For word and string
	}

	this(string s)
	{
		this.s = s;
		line = column = 1;
		popFront();
	}

	Token front;
	bool empty = false;

	void popFront()
	{
		while (s.length && (s[0] == ' ' || s[0] == '\t'))
			advance();

		if (!s.length)
		{
			front = Token(Token.Type.eof);
			empty = true;
			return;
		}

		switch (s[0])
		{
			case '\n':
			case '\r':
			case ';':
				front = Token(Token.Type.nodeDelim);
				advance();
				return;
			case '{':
				front = Token(Token.Type.beginStruct);
				advance();
				return;
			case '}':
				front = Token(Token.Type.endStruct);
				advance();
				return;
			case '[':
				front = Token(Token.Type.beginData);
				advance();
				return;
			case ']':
				front = Token(Token.Type.endData);
				advance();
				return;
			case '"':
				front = Token(Token.Type.string, readString());
				return;
			default:
				front = Token(Token.Type.word, readWord());
				enforce(front.value.length, "Syntax error: Invalid character " ~ s[0]);
				return;
		}
	}

	struct Position { int line, column; }
	@property Position position() { return Position(line, column); }

private:
	string s;
	int line, column;

	void advance(size_t num = 1)
	{
		foreach (char c; s[0..num])
			if (c == '\n')
			{
				line++;
				column = 1;
			}
			else
				column++;
		s = s[num..$];
	}

	static bool isWordChar(char c)
	{
		return isTagChar(c)
			|| c == '/' || c == '+' || c == '=' // Base64 data
			|| c == '-' || c == ':'             // Timestamps
		;
	}

	string readString()
	{
		// TODO: WYSIWYG strings
		assert(s.length && s[0] == '"');
		advance();
		string result;
		size_t p = 0;
		while (true)
		{
			enforce(s.length, "Unexpected EOF within string literal");
			switch (s[p])
			{
				case '"':
					if (result.length)
						result ~= s[0..p];
					else
						result = s[0..p];
					advance(p+1);
					return result;
				case '\\':
					if (result.length)
						result ~= s[0..p];
					else
						result = s[0..p];
					advance(p+1);
					p = 0;
					break;
				default:
					p++;
					break;
			}
		}
	}

	string readWord()
	{
		auto p = 0;
		while (p < s.length && isWordChar(s[p]))
			p++;
		auto result = s[0..p];
		advance(p);
		return result;
	}
}
