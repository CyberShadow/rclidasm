module main;

import std.file;
import std.path;

import rclidasm.assembler;
import rclidasm.clifile;
import rclidasm.disassembler;

import ae.utils.funopt;
import ae.utils.main;

struct RCLIDAsm
{
static:
	@(`Disassemble CLI executable to .rcli file`)
	void disassemble(string fileName)
	{
		auto exe = cast(ubyte[])read(fileName);
		auto cli = CLIFile(exe);
		auto disassembler = Disassembler(&cli);
		auto disassembly = disassembler.disassemble();
		write(fileName ~ ".rcli", disassembly);
	}

	@(`Assemble CLI executable from .rcli file`)
	void assemble(string fileName)
	{
		auto disassembly = readText(fileName);
		auto assembler = Assembler(disassembly);
		auto cli2 = assembler.assemble();
		auto exe2 = cli2.compile();
		write("hello2.exe", exe2);
		write(fileName.stripExtension, disassembly);
	}
}

mixin ae.utils.main.main!(funoptDispatch!RCLIDAsm);
