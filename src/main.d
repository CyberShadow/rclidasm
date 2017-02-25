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
