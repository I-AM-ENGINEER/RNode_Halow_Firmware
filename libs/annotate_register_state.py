#!/usr/bin/env python3
"""
Annotate assembly with lightweight symbolic register state.

This pass keeps a best-effort symbolic value per register and appends comments
for instructions that write registers. The goal is readability during reverse
engineering, not full correctness across all control-flow joins.
"""

import re

FUNC_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:(?:\s*//.*)?$")
INSN_RE = re.compile(r"^(\s+)([0-9a-f]+):\s+([0-9a-f ]+)\s+([.\w]+)\s*(.*?)(\s*//.*)?$")
REG_RE = re.compile(r"\br([0-9]+)\b")
OBJDUMP_TARGET_RE = re.compile(r"//\s*[0-9a-f]+\s+<[^>]+>")
OFFSET_EXPR_RE = re.compile(r"^\((.+)\s([+-])\s(0x[0-9a-f]+)\)$")
CALL_TARGET_RE = re.compile(r"<([^>]+)>")


def init_state():
    state = {f"r{i}": f"r{i}" for i in range(32)}
    state["r0"] = "<arg0>"
    state["r1"] = "<arg1>"
    state["r2"] = "<arg2>"
    state["r3"] = "<arg3>"
    state["r14"] = "sp"
    state["r15"] = "lr"
    return state


def split_operands(text):
    if not text:
        return []
    parts = []
    current = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def regs_in_text(text):
    return [f"r{m.group(1)}" for m in REG_RE.finditer(text or "")]


def fmt_value(text):
    text = text.strip()
    if re.fullmatch(r"-?\d+", text) or text.startswith("0x") or text.startswith("-0x"):
        value = parse_int(text)
        if value is not None:
            return fmt_int(value)
    return text


def parse_int(text):
    try:
        return int(text, 0)
    except (TypeError, ValueError):
        return None


def fmt_int(value):
    if value < 0:
        value &= 0xFFFFFFFF
    return f"0x{value:x}"


def strip_outer_parens(expr):
    expr = expr.strip()
    if not (expr.startswith("(") and expr.endswith(")")):
        return expr

    depth = 0
    for index, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and index != len(expr) - 1:
                return expr
    return expr[1:-1].strip()


def split_const_offset(expr):
    expr = expr.strip()
    match = OFFSET_EXPR_RE.match(expr)
    if not match:
        return expr, 0

    base_expr, op, imm_text = match.groups()
    imm_value = parse_int(imm_text)
    if imm_value is None:
        return expr, 0

    root, offset = split_const_offset(base_expr)
    if op == "-":
        imm_value = -imm_value
    return root, offset + imm_value


def with_offset(expr, delta):
    expr = expr.strip()
    if delta == 0:
        return expr

    root, base_delta = split_const_offset(expr)
    total = base_delta + delta

    root_value = parse_int(root)
    if root_value is not None:
        return fmt_int(root_value + total)

    if total < 0:
        return f"({root} - {fmt_int(-total)})"
    return f"({root} + {fmt_int(total)})"


def stack_slot_name(expr):
    root, offset = split_const_offset(expr)
    if root != "sp":
        return None
    if offset < 0:
        return f"local_{-offset:x}"
    if offset > 0:
        return f"stack_p{offset:x}"
    return "stack_0"


def mem_expr(operand, state):
    # (r2, 0xc)
    match = re.match(r"\((r\d+),\s*(0x[0-9a-f]+|\d+)\)", operand)
    if match:
        base = state.get(match.group(1), match.group(1))
        off = parse_int(match.group(2))
        if off is None:
            return operand
        target = with_offset(base, off)
        slot_name = stack_slot_name(target)
        if slot_name is not None:
            return slot_name
        return f"*({target})"

    # (r2, r0 << 2)
    match = re.match(r"\((r\d+),\s*(r\d+)\s*<<\s*(\d+)\)", operand)
    if match:
        base = state.get(match.group(1), match.group(1))
        idx = state.get(match.group(2), match.group(2))
        sh = match.group(3)
        return f"*({base} + ({idx} << {sh}))"

    # (r2, r0)
    match = re.match(r"\((r\d+),\s*(r\d+)\)", operand)
    if match:
        base = state.get(match.group(1), match.group(1))
        idx = state.get(match.group(2), match.group(2))
        return f"*({base} + {idx})"

    return operand


def simplify_deref_text(text):
    text = text.strip()
    text = re.sub(r"\*\(\(([^()]+)\)\)", r"*(\1)", text)
    text = re.sub(r"\+\s0x0\)", ")", text)
    return text


def unary(op, value, imm=None):
    return f"{op}({value})" if imm is None else f"{op}({value}, {imm})"


def binary(left, op, right):
    return f"({left} {op} {right})"


def bitnot(value):
    return f"(~{value})"


def simplify_shift_arith(left, op, right):
    left_int = parse_int(left)
    right_int = parse_int(right)
    if left_int is None or right_int is None:
        return binary(left, op, right)

    if op == "+":
        return fmt_int(left_int + right_int)
    if op == "-":
        return fmt_int(left_int - right_int)
    if op == "<<":
        return fmt_int(left_int << right_int)
    if op == ">>":
        return fmt_int(left_int >> right_int)
    return binary(left, op, right)


def update_state(state, mnemonic, operands, offset=None, comment=""):
    ops = split_operands(operands)
    written = []
    mem_write = None

    def write(reg, value):
        state[reg] = simplify_deref_text(value)
        written.append(reg)

    if mnemonic == "mov" and len(ops) == 2:
        write(ops[0], state.get(ops[1], ops[1]))
        return written

    if mnemonic in {"movi", "lrw"} and len(ops) == 2:
        write(ops[0], fmt_value(ops[1]))
        return written

    if mnemonic == "movih" and len(ops) == 2:
        write(ops[0], f"({fmt_value(ops[1])} << 0x10)")
        return written

    if mnemonic in {"addi", "subi", "lsli", "lsri", "asri", "rotli"} and len(ops) in {2, 3}:
        if len(ops) == 2:
            dst = ops[0]
            srcv = state.get(dst, dst)
            imm = fmt_value(ops[1])
        else:
            dst, src, imm = ops
            srcv = state.get(src, src)
            imm = fmt_value(imm)
        opmap = {
            "addi": "+",
            "subi": "-",
            "lsli": "<<",
            "lsri": ">>",
            "asri": ">>",
            "rotli": "rotl",
        }
        if mnemonic == "rotli":
            write(dst, unary("rotl", srcv, imm))
        else:
            write(dst, simplify_shift_arith(srcv, opmap[mnemonic], imm))
        return written

    if mnemonic in {"andi", "ori", "xori"}:
        if len(ops) == 3:
            dst, src, imm = ops
            srcv = state.get(src, src)
        elif len(ops) == 2:
            dst, imm = ops
            srcv = state.get(dst, dst)
        else:
            return written
        opmap = {"andi": "&", "ori": "|", "xori": "^"}
        write(dst, binary(srcv, opmap[mnemonic], fmt_value(imm)))
        return written

    if mnemonic in {"and", "or", "xor", "addu", "subu", "mult", "divu", "divs"} and len(ops) in {2, 3}:
        if len(ops) == 2:
            dst, src = ops
            left = state.get(dst, dst)
            right = state.get(src, src)
        else:
            dst, left_src, right_src = ops
            left = state.get(left_src, left_src)
            right = state.get(right_src, right_src)
        opmap = {
            "and": "&",
            "or": "|",
            "xor": "^",
            "addu": "+",
            "subu": "-",
            "mult": "*",
            "divu": "/",
            "divs": "/",
        }
        write(dst, binary(left, opmap[mnemonic], right))
        return written

    if mnemonic in {"nor", "not"} and len(ops) in {1, 2, 3}:
        if mnemonic == "not":
            dst = ops[0]
            src = ops[1] if len(ops) > 1 else dst
            write(dst, bitnot(state.get(src, src)))
            return written

        if len(ops) == 1:
            dst = ops[0]
            write(dst, bitnot(state.get(dst, dst)))
            return written
        if len(ops) == 2:
            dst, src = ops
            if dst == src:
                write(dst, bitnot(state.get(src, src)))
            else:
                write(dst, bitnot(binary(state.get(dst, dst), "|", state.get(src, src))))
            return written
        if len(ops) == 3:
            dst, left_src, right_src = ops
            left = state.get(left_src, left_src)
            right = state.get(right_src, right_src)
            write(dst, bitnot(binary(left, "|", right)))
            return written

    if mnemonic in {"zext", "sext"} and len(ops) >= 2:
        dst, src = ops[0], ops[1]
        write(dst, unary(mnemonic, state.get(src, src)))
        return written

    if mnemonic == "zexth" and len(ops) == 2:
        dst, src = ops
        write(dst, unary("zext16", state.get(src, src)))
        return written

    if mnemonic == "zextb" and len(ops) == 2:
        dst, src = ops
        write(dst, unary("zext8", state.get(src, src)))
        return written

    if mnemonic == "sexth" and len(ops) == 2:
        dst, src = ops
        write(dst, unary("sext16", state.get(src, src)))
        return written

    if mnemonic == "sextb" and len(ops) == 2:
        dst, src = ops
        write(dst, unary("sext8", state.get(src, src)))
        return written

    if mnemonic in {"bclri", "bseti"} and len(ops) in {2, 3}:
        if len(ops) == 2:
            dst, bit = ops
            srcv = state.get(dst, dst)
        else:
            dst, src, bit = ops
            srcv = state.get(src, src)
        bitv = fmt_value(bit)
        if mnemonic == "bclri":
            write(dst, f"({srcv} & ~(0x1 << {bitv}))")
        else:
            write(dst, f"({srcv} | (0x1 << {bitv}))")
        return written

    if mnemonic.startswith("ld.") and len(ops) == 2:
        dst, mem = ops
        write(dst, mem_expr(mem, state))
        return written

    if mnemonic.startswith("ldr.") and len(ops) == 2:
        dst, mem = ops
        write(dst, mem_expr(mem, state))
        return written

    if mnemonic in {"mvc", "mvcv"} and len(ops) == 1:
        write(ops[0], "<cond>")
        return written

    if mnemonic.startswith("st.") and len(ops) == 2:
        src, mem = ops
        srcv = state.get(src, src)
        mem_write = simplify_deref_text(f"{mem_expr(mem, state)} = {srcv}")
        return written, mem_write

    if mnemonic == "bsr":
        target_match = CALL_TARGET_RE.search(comment or "")
        if target_match:
            target = target_match.group(1)
            call_site = f"0x{offset.lower()}" if offset is not None else "?"
            state["r0"] = f"<ret {target}@{call_site}>"
        else:
            state["r0"] = "<ret>"
        state["r1"] = "<clobbered>"
        state["r2"] = "<clobbered>"
        state["r3"] = "<clobbered>"
        return ["r0", "r1", "r2", "r3"]

    return written


def annotate_lines(lines):
    state = init_state()
    output = []

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if FUNC_RE.match(line):
            state = init_state()
            output.append(line)
            continue

        match = INSN_RE.match(line)
        if not match:
            output.append(line)
            continue

        indent, offset, raw_bytes, mnemonic, operands, comment = match.groups()
        operands = operands.rstrip()
        comment = comment or ""
        comment = OBJDUMP_TARGET_RE.sub("", comment).rstrip()
        result = update_state(state, mnemonic, operands, offset=offset, comment=comment)
        mem_write = None
        if isinstance(result, tuple):
            written, mem_write = result
        else:
            written = result

        extras = []
        if written:
            regs = ", ".join(f"{reg}={state.get(reg, reg)}" for reg in written[:2])
            extras.append(f"regs: {regs}")
        if mem_write:
            extras.append(mem_write)

        if extras:
            extra_text = "; ".join(extras)
            if comment:
                line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}{comment}; {extra_text}"
            else:
                line = f"{indent}{offset}:\t{raw_bytes}\t{mnemonic}\t{operands}\t// {extra_text}"

        output.append(line)

    return output
