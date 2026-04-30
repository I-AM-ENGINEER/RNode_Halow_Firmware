#!/usr/bin/env python3
"""
Annotate relocation-resolved callsites with inferred argument byte counts.

This pass is intentionally conservative.
It only annotates calls to callees defined in the same assembly file.
"""

import re

ARG_REGS = ("r0", "r1", "r2", "r3")
REG_RE = re.compile(r"\br([0-9]+)\b")
FUNC_RE = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
INSN_RE = re.compile(r"^(\s+)([0-9a-f]+):\s+([0-9a-f ]+)\s+([.\w]+)\s*(.*?)(\s*//.*)?$")
TARGET_RE = re.compile(r"// <([^>]+)> \[reloc\]")


def split_operands(text):
    if not text:
        return []
    return [part.strip() for part in text.split(",")]


def regs_in_text(text):
    return [f"r{m.group(1)}" for m in REG_RE.finditer(text or "")]


def operand_regs(operands):
    regs = []
    for op in split_operands(operands):
        regs.extend(regs_in_text(op))
    return regs


def rw_for_instruction(mnemonic, operands):
    ops = split_operands(operands)
    regs = operand_regs(operands)
    reads = set()
    writes = set()

    if mnemonic == "mov" and len(ops) == 2:
        writes.add(ops[0])
        reads.update(regs_in_text(ops[1]))
        return reads, writes

    if mnemonic in {"movi", "lrw", "movih"} and len(ops) >= 1:
        writes.add(ops[0])
        return reads, writes

    if mnemonic in {"addi", "subi", "lsli", "lsri", "asri", "rotli", "bseti", "bclri"} and len(ops) >= 1:
        writes.add(ops[0])
        reads.add(ops[0])
        if len(ops) > 1:
            reads.update(regs_in_text(",".join(ops[1:])))
        return reads, writes

    if mnemonic in {"andi", "ori", "xori"}:
        if len(ops) == 3:
            writes.add(ops[0])
            reads.update(regs_in_text(ops[1]))
        elif len(ops) >= 1:
            writes.add(ops[0])
            reads.add(ops[0])
            reads.update(regs_in_text(",".join(ops[1:])))
        return reads, writes

    if mnemonic in {"addu", "subu", "and", "or", "xor", "mult", "divs"} and len(ops) >= 2:
        writes.add(ops[0])
        reads.add(ops[0])
        reads.update(regs_in_text(ops[1]))
        return reads, writes

    if mnemonic in {"zext", "sext"} and len(ops) >= 2:
        writes.add(ops[0])
        reads.update(regs_in_text(ops[1]))
        return reads, writes

    if mnemonic in {"mvc", "mvcv"} and len(ops) >= 1:
        writes.add(ops[0])
        return reads, writes

    if mnemonic.startswith("ld.") or mnemonic.startswith("ldr."):
        if len(ops) >= 1:
            writes.add(ops[0])
        if len(ops) > 1:
            reads.update(regs_in_text(",".join(ops[1:])))
        return reads, writes

    if mnemonic.startswith("st."):
        reads.update(regs)
        return reads, writes

    if mnemonic in {"cmpnei", "cmphsi", "cmpne", "cmplt", "cmphs", "bez", "bnez", "bt", "bf", "blz", "bhsz"}:
        reads.update(regs)
        return reads, writes

    if mnemonic in {"push", "pop"}:
        reads.update(regs)
        writes.update(regs if mnemonic == "pop" else [])
        return reads, writes

    if mnemonic == "bsr":
        writes.update(ARG_REGS)
        writes.add("r15")
        return reads, writes

    if mnemonic in {"jmp", "br"}:
        reads.update(regs)
        return reads, writes

    if ops:
        reads.update(regs_in_text(",".join(ops[1:])))
        if mnemonic.startswith(("cmp", "bt", "bf", "b", "j")) or mnemonic.startswith("st"):
            reads.update(regs_in_text(ops[0]))
            return reads, writes
        writes.add(ops[0]) if ops[0] in ARG_REGS or ops[0].startswith("r") else None
        if ops[0] in writes:
            if mnemonic not in {"movi", "lrw", "movih"}:
                reads.add(ops[0])
        return reads, writes

    return reads, writes


def contiguous_arg_bytes(used_regs):
    count = 0
    for reg in ARG_REGS:
        if reg in used_regs:
            count += 1
        else:
            break
    return count * 4


def infer_function_arg_bytes(lines):
    functions = {}
    current = None
    current_lines = []

    def flush():
        if current is None:
            return
        functions[current] = summarize_function(current_lines)

    for line in lines:
        stripped = line.rstrip("\n")
        match = FUNC_RE.match(stripped)
        if match:
            flush()
            current = match.group(1)
            current_lines = []
            continue
        if current is not None:
            current_lines.append(stripped)
    flush()
    return functions


def summarize_function(lines):
    seen_write = set()
    used_before_def = set()

    for line in lines:
        match = INSN_RE.match(line)
        if not match:
            continue
        mnemonic = match.group(4)
        operands = match.group(5).rstrip()
        reads, writes = rw_for_instruction(mnemonic, operands)

        for reg in ARG_REGS:
            if reg in reads and reg not in seen_write:
                used_before_def.add(reg)

        for reg in writes:
            if reg in ARG_REGS:
                seen_write.add(reg)

    return contiguous_arg_bytes(used_before_def)


def annotate_lines(lines):
    func_arg_bytes = infer_function_arg_bytes(lines)
    output = []

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        func_match = FUNC_RE.match(line)
        if func_match:
            func_name = func_match.group(1)
            arg_bytes = func_arg_bytes.get(func_name)
            if arg_bytes is not None:
                line = f"{line} // arg_bytes: {arg_bytes}"
            output.append(line)
            continue

        match = INSN_RE.match(line)
        if not match:
            output.append(line)
            continue

        indent, offset, raw_bytes, mnemonic, operands, comment = match.groups()
        operands = operands.rstrip()
        comment = comment or ""

        target_match = TARGET_RE.search(comment)
        if mnemonic == "bsr" and target_match:
            target = target_match.group(1)
            arg_bytes = func_arg_bytes.get(target)
            if arg_bytes is not None:
                line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}{comment} // arg_bytes: {arg_bytes}"
            output.append(line)
            continue

        output.append(line)

    return output
