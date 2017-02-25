module rclidasm.writer;

import std.base64;
import std.range;
import std.string;

import rclidasm.common;

struct Writer
{
	void beginTag(string s)
	{
		putIndent();
		debug foreach (char c; s)
			assert(isTagChar(c), "Bad tag name: " ~ s);
		buf.put(s);
	}

	void endTag()
	{
		buf.put("\n");
	}

	void beginStruct()
	{
		buf.put(" {\n");
		indent++;
	}

	void endStruct()
	{
		indent--;
		putIndent();
		buf.put("}");
	}

	void putValue(in char[] s)
	{
		buf.put(" ");
		buf.put(s);
	}

	void putString(in char[] s)
	{
		// TODO: use WYSIWYG literals when appropriate
		buf.put(` "`);
		foreach (char c; s)
			if (c < 0x20)
				buf.put(`\x%02X`.format(c)); // TODO: Don't allocate
			else
			{
				if (c == '"' || c == '\\')
					buf.put('\\');
				buf.put(c);
			}
		buf.put('"');
	}

	void putData(in ubyte[] s)
	{
		buf.put(" [");
		// TODO: Don't allocate
		if (s.length <= 64)
			buf.put(Base64.encode(s));
		else
		{
			buf.put("\n");
			indent++;
			foreach (c; s.chunks(48))
			{
				putIndent();
				buf.put(Base64.encode(c));
				buf.put("\n");
			}
			indent--;
			putIndent();
		}
		buf.put("]");
	}

	@property string data() { return buf.data; }

private:
	uint indent;

	void putIndent()
	{
		foreach (i; 0..indent)
			buf.put("  ");
	}
	
	import std.array : Appender;
	Appender!string buf;
}
