#pragma once

SIG_DESCRIPTOR *GenerateSigFromCode(duint Start, duint End);
void PatternScan(SIG_DESCRIPTOR *Descriptor, std::vector<duint>& Results);

bool MatchOperands(_DInst *Instruction, _Operand *Operands, int PrefixSize);
int MatchInstruction(_DInst *Instruction, PBYTE Data);