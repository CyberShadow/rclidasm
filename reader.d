module reader;

import std.exception;
import std.string;

import tokenizer;

/// SDLang parser (on top of tokenizer).
struct Reader
{
	@disable this();

	this(string s)
	{
		tokenizer = Tokenizer(s);
	}

	/// Return the name of the next tag.
	/// Throws if the next object is not a tag.
	string readTag()
	{
		skipDelims();
		return readWord();
	}

	/// If the next token is a tag with the given name, skip over it. Throw otherwise.
	void expectTag(string name)
	{
		auto tag = readTag();
		enforce(tag == name, "'%s' expected, not '%s'".format(name, tag));
	}

	/// Return the next word as a string.
	string readWord()
	{
		return expect(Tokenizer.Token.Type.word).value;
	}

	/// Skip past a node delimiter. Throws otherwise.
	void endNode()
	{
		expect(Tokenizer.Token.Type.nodeDelim);
	}

	/// If the next token is a node delimiter, return true and skip it.
	bool skipEndNode()
	{
		return skipOver(Tokenizer.Token.Type.nodeDelim);
	}

	/// Skip past a {. Throws otherwise.
	void beginStruct()
	{
		expect(Tokenizer.Token.Type.beginStruct);
	}

	/// Skip past a }. Throws otherwise.
	void endStruct()
	{
		expect(Tokenizer.Token.Type.endStruct);
	}

	/// If the next token is }, return true and skip it.
	bool skipEndStruct()
	{
		skipDelims();
		return skipOver(Tokenizer.Token.Type.endStruct);
	}

	/// Return the value of the next string literal.
	/// Throws if the next object is not a string literal.
	string readString()
	{
		return expect(Tokenizer.Token.Type.string).value;
	}

	/// Skip past a [. Throws otherwise.
	void beginData()
	{
		expect(Tokenizer.Token.Type.beginData);
	}

	/// Read and return the next Base64 data block.
	alias readData = readTag;

	/// If the next token is ], return true and skip it.
	bool skipEndData()
	{
		skipDelims();
		return skipOver(Tokenizer.Token.Type.endData);
	}

	@property Tokenizer.Position position() { return tokenizer.position; }

private:
	Tokenizer tokenizer;

	/// Skip over node delimiters.
	void skipDelims()
	{
		while (tokenizer.front.type == Tokenizer.Token.Type.nodeDelim)
			tokenizer.popFront();
	}

	/// Consume a token of the indicated type and return it, throw otherwise.
	Tokenizer.Token expect(Tokenizer.Token.Type type)
	{
		enforce(tokenizer.front.type == type, "%s expected, not %s".format(type, tokenizer.front));
		auto token = tokenizer.front;
		tokenizer.popFront();
		return token;
	}

	/// If the next token is of the given type, return true and skip over it.
	bool skipOver(Tokenizer.Token.Type type)
	{
		if (tokenizer.front.type == type)
		{
			tokenizer.popFront();
			return true;
		}
		return false;
	}
}
