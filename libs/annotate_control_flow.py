#!/usr/bin/env python3
"""
Annotate C-SKY assembly with lightweight control-flow comments.

This pass:
- inserts local labels for branch targets within a function
- appends pseudo-C comments for common branch/jump forms
"""

import re

FUNC_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:(?:\s*//.*)?$")
INSN_RE = re.compile(r"^(\s+)([0-9a-f]+):\s+([0-9a-f ]+)\s+([.\w]+)\s*(.*?)(\s*//.*)?$")
OBJDUMP_TARGET_RE = re.compile(r"//\s*[0-9a-f]+\s+<[^>]+>")


def split_operands(text):
    if not text:
        return []
    return [part.strip() for part in text.split(",")]


def fmt_op(text):
    text = text.strip()
    try:
        value = int(text, 0)
    except ValueError:
        return text
    if value < 0:
        value &= 0xFFFFFFFF
    return f"0x{value:x}"


def parse_target_hex(operands):
    for op in split_operands(operands):
        match = re.match(r"0x([0-9a-f]+)", op)
        if match:
            return match.group(1).lower()
    return None


def invert_condition(text):
    swaps = {
        " == ": " != ",
        " != ": " == ",
        " >= ": " < ",
        " < ": " >= ",
        " > ": " <= ",
        " <= ": " > ",
    }
    for old, new in swaps.items():
        if old in text:
            return text.replace(old, new, 1)
    return f"!({text})"


def condition_from_compare(mnemonic, operands):
    ops = split_operands(operands)
    if len(ops) != 2:
        return None

    left = ops[0]
    right = fmt_op(ops[1])
    mapping = {
        "cmpnei": "!=",
        "cmpeqi": "==",
        "cmphsi": ">=",
        "cmplti": "<",
        "cmphi": ">",
        "cmplsi": "<=",
    }
    op = mapping.get(mnemonic)
    if op:
        return f"{left} {op} {right}"
    return None


def branch_comment(mnemonic, operands, target_hex, last_condition=None):
    ops = split_operands(operands)
    label = f"loc_{target_hex}"

    if mnemonic == "bnez" and len(ops) >= 1:
        return f"if ({ops[0]} != 0x0) goto {label};"
    if mnemonic == "bez" and len(ops) >= 1:
        return f"if ({ops[0]} == 0x0) goto {label};"
    if mnemonic == "bt":
        cond = last_condition or "T"
        return f"if ({cond}) goto {label};"
    if mnemonic == "bf":
        cond = invert_condition(last_condition) if last_condition else "!T"
        return f"if ({cond}) goto {label};"
    if mnemonic == "blz" and len(ops) >= 1:
        return f"if ({ops[0]} < 0x0) goto {label};"
    if mnemonic == "bhsz" and len(ops) >= 1:
        return f"if ({ops[0]} >= 0x0) goto {label};"
    if mnemonic == "br":
        return f"goto {label};"
    return None


def jump_comment(mnemonic, operands):
    ops = split_operands(operands)
    if mnemonic != "jmp" or not ops:
        return None
    if ops[0] == "r15":
        return "return;"
    return f"goto *{ops[0]};"


def collect_function_blocks(lines):
    blocks = []
    current_header = None
    current_body = []

    def flush():
        if current_header is not None:
            blocks.append((current_header, current_body[:]))

    for line in lines:
        stripped = line.rstrip("\n")
        match = FUNC_RE.match(stripped)
        if match:
            flush()
            current_header = stripped
            current_body = []
        elif current_header is not None:
            current_body.append(stripped)
        else:
            blocks.append((None, [stripped]))

    flush()
    return blocks


def annotate_function(header, body):
    targets = set()
    for line in body:
        match = INSN_RE.match(line)
        if not match:
            continue
        mnemonic = match.group(4)
        operands = match.group(5).rstrip()
        if mnemonic in {"bnez", "bez", "bt", "bf", "blz", "bhsz", "br"}:
            target_hex = parse_target_hex(operands)
            if target_hex is not None:
                targets.add(target_hex)

    output = [header]
    last_condition = None
    for line in body:
        match = INSN_RE.match(line)
        if not match:
            last_condition = None
            output.append(line)
            continue

        indent, offset, raw_bytes, mnemonic, operands, comment = match.groups()
        operands = operands.rstrip()
        comment = comment or ""
        comment = OBJDUMP_TARGET_RE.sub("", comment).rstrip()

        if offset.lower() in targets:
            output.append(f"loc_{offset.lower()}:")

        extra_comment = None
        compare_condition = condition_from_compare(mnemonic, operands)
        if compare_condition:
            last_condition = compare_condition
        if mnemonic in {"bnez", "bez", "bt", "bf", "blz", "bhsz", "br"}:
            target_hex = parse_target_hex(operands)
            if target_hex is not None:
                extra_comment = branch_comment(mnemonic, operands, target_hex, last_condition)
            last_condition = None
        elif mnemonic == "jmp":
            extra_comment = jump_comment(mnemonic, operands)
            last_condition = None
        elif mnemonic not in {
            "cmphsi",
            "cmpnei",
            "cmpeqi",
            "cmplti",
            "cmphi",
            "cmplsi",
        }:
            last_condition = None

        if extra_comment:
            if comment:
                line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}{comment}; {extra_comment}"
            else:
                line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}\t// {extra_comment}"
        elif not comment:
            line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}"
        else:
            line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}{comment}"

        output.append(line)

    return output


def annotate_lines(lines):
    output = []
    for header, body in collect_function_blocks(lines):
        if header is None:
            output.extend(body)
        else:
            output.extend(annotate_function(header, body))
    return output
