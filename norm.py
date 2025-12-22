#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 @federicofantini
#
# This file is part of MalCluster.
#
# MalCluster is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MalCluster is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/gpl-3.0.html>
#
__author__ = "@federicofantini"
__license__ = "GPLv3"

import re

# Immediate values: hex 0x..., including 0x00
RE_IMM = re.compile(r"\b0x[0-9a-fA-F]+\b")

# Registers (ALL x86/x64: GP, partials, SIMD, MMX, CR, DR)
RE_REG = re.compile(
    r"\b("
    # 64-bit GP
    r"rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|"
    r"r8|r9|r10|r11|r12|r13|r14|r15|"

    # 32-bit GP
    r"eax|ebx|ecx|edx|esi|edi|ebp|esp|"
    r"r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d|"

    # 16-bit GP
    r"ax|bx|cx|dx|si|di|bp|sp|"
    r"r8w|r9w|r10w|r11w|r12w|r13w|r14w|r15w|"

    # 8-bit classic
    r"al|bl|cl|dl|ah|bh|ch|dh|"

    # 8-bit low registers (new ABI)
    r"sil|dil|spl|bpl|"
    r"r8b|r9b|r10b|r11b|r12b|r13b|r14b|r15b|"

    # MMX
    r"mm[0-7]|"

    # XMM
    r"xmm([0-9]|1[0-9]|2[0-9]|3[0-1])|"

    # YMM
    r"ymm([0-9]|1[0-9]|2[0-9]|3[0-1])|"

    # ZMM
    r"zmm([0-9]|1[0-9]|2[0-9]|3[0-1])|"

    # Control registers
    r"cr[0-8]|"

    # Debug registers
    r"dr[0-7]"
    r")\b",
    flags=re.IGNORECASE
)

# Registers to preserve during normalization
REG_PRESERVE = re.compile(r"\b(ebp|rbp|esp|rsp|cs|ds|es|fs|gs|ss)\b", re.IGNORECASE)

# Memory with imported function labels: [user32.wsprintfW]
RE_MEMLABEL = re.compile(r"\[[A-Za-z0-9_]+\.[A-Za-z0-9_@]+\]")

# Segment-prefixed memory operands: fs:[...], gs:[...], etc.
RE_SEG_MEM = re.compile(r"(fs|gs|ds|es):\[[^\]]+\]", flags=re.IGNORECASE)

# Generic memory operands
RE_MEM = re.compile(r"\[[^\]]+\]")

# Label declarations like "loc_40110d:"
RE_LABEL_DECL = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*:\s*$")

# Remove ptr types: byte ptr, word ptr, dword ptr, qword ptr, etc.
RE_PTR = re.compile(r"\b(?:byte|word|dword|qword|tword)\s+ptr\b", flags=re.IGNORECASE)

# Frame arguments: [ebp+offset], [rbp+offset]
RE_FRAME_ARG = re.compile(r"\[(?:e|r)bp\+[^\]]+\]", flags=re.IGNORECASE)

# Frame locals: [ebp-offset], [rbp-offset]
RE_FRAME_LOCAL = re.compile(r"\[(?:e|r)bp\-[^\]]+\]", flags=re.IGNORECASE)

# Stack temporaries: [esp+offset], [rsp+offset]
RE_STACK_TEMP = re.compile(r"\[(?:e|r)sp\+[^\]]+\]", flags=re.IGNORECASE)

# Stack locals: [esp-offset], [rsp-offset]
RE_STACK_LOCAL = re.compile(r"\[(?:e|r)sp\-[^\]]+\]", flags=re.IGNORECASE)

# Windows user folder path
RE_WIN_USER = re.compile(r"C:\\Users\\[^\\]+\\", flags=re.IGNORECASE)

def fully_normalize(instruction: str) -> str:
    """
    Fully normalisation using the whole regex set.
    """
    line = instruction.strip()
    if not line:
        return ""

    # label like "loc_40110d:"
    if RE_LABEL_DECL.match(line):
        return "label"

    # Split mnemonic and operands
    parts = line.split(maxsplit=1)
    mnemonic = parts[0].lower()
    operands = parts[1] if len(parts) > 1 else ""

    ops = operands

    # Remove ptr annotations
    ops = RE_PTR.sub("", ops)

    # Normalize memory in correct order: specific → generic
    ops = RE_MEMLABEL.sub("MEM", ops)     # [dll.func]
    ops = RE_SEG_MEM.sub("MEM", ops)      # fs:[...], gs:[...]
    ops = RE_MEM.sub("MEM", ops)          # [...]

    # Immediates and registers
    ops = RE_IMM.sub("IMM", ops)
    ops = RE_REG.sub("REG", ops)

    # Normalize spacing and commas
    ops = ops.replace(",", " ,")
    ops = re.sub(r"\s+", " ", ops).strip()

    return mnemonic if not ops else f"{mnemonic} {ops}"

def normalize(instruction: str, fully: bool) -> str:
    """
    Normalize assembly instruction: registers, immediates, memory, labels, ptr types, segments, imports
    """
    
    # Choose full or partial normalization
    if fully:
        return fully_normalize(instruction)

    line = instruction.strip()
    if not line:
        return ""

    # label like "loc_40110d:"
    if RE_LABEL_DECL.match(line):
        return "label"

    # Split mnemonic and operands
    parts = line.split(maxsplit=1)
    mnemonic = parts[0].lower()
    operands = parts[1] if len(parts) > 1 else ""

    ops = operands

    # Remove ptr annotations (byte ptr, dword ptr, etc.)
    ops = RE_PTR.sub("", ops)

    # Preserve call to imported functions
    if mnemonic == "call" and RE_MEMLABEL.search(ops):
        ops = RE_MEMLABEL.sub(lambda m: m.group(0), ops)
    else:
        # Memory normalization for imported functions
        ops = RE_MEMLABEL.sub("MEM", ops)
        ops = RE_SEG_MEM.sub("MEM", ops)

        # Stack/frame accesses
        ops = RE_FRAME_ARG.sub("FRAME_ARG", ops)
        ops = RE_FRAME_LOCAL.sub("FRAME_LOCAL", ops)
        ops = RE_STACK_TEMP.sub("STACK_TEMP", ops)
        ops = RE_STACK_LOCAL.sub("STACK_LOCAL", ops)

        # Generic memory operands (exclude stack/frame/segment registers)
        def mem_replacer(match):
            mem = match.group(0)
            if (RE_FRAME_ARG.match(mem) or RE_FRAME_LOCAL.match(mem) or
                RE_STACK_TEMP.match(mem) or RE_STACK_LOCAL.match(mem) or
                RE_SEG_MEM.match(mem)):
                return mem
            return "MEM"
        ops = RE_MEM.sub(mem_replacer, ops)

    # Normalize registers except ebp/rbp, esp/rsp, and segment registers
    def reg_sub(match):
        reg = match.group(0).lower()
        if REG_PRESERVE.fullmatch(reg):
            return reg  # do not normalize
        return "REG"
        
    ops = RE_REG.sub(reg_sub, ops)

    # Normalize spacing and commas
    ops = ops.replace(",", " ,")
    ops = re.sub(r"\s+", " ", ops).strip()

    return mnemonic if not ops else f"{mnemonic} {ops}"

def normalize_windows_user_path(path: str) -> str:
    """
    Normalize windows user in folder path.
    """
    return re.sub(RE_WIN_USER, r"C:\\Users\\*\\", path)