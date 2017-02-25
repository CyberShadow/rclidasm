import std.exception;
import std.file;

import rclidasm.assembler;
import rclidasm.clifile;
import rclidasm.disassembler;

void main()
{
	auto exe = cast(ubyte[])read("hello.exe");
	auto cli = CLIFile(exe);
	auto disassembler = Disassembler(&cli);
	auto disassembly = disassembler.disassemble();
	write("hello.rcli", disassembly);
	auto assembler = Assembler(disassembly);
	auto cli2 = assembler.assemble();
	auto exe2 = cli2.compile();
	write("hello2.exe", exe2);
	auto cli3 = CLIFile(exe2);
	auto disassembler2 = Disassembler(&cli3);
	auto disassembly2 = disassembler2.disassemble();
	write("hello2.rcli", disassembly2);

	enforce(exe == exe2, "exe -> rcli -> exe roundtrip failed");
	enforce(disassembly == disassembly2, "rcli -> exe -> rcli roundtrip failed");
}
