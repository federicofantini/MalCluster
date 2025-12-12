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

"""
Pipeline for extracting static analysis artefacts using the Malcat Python API.

This module performs the following steps:
    • Extracts printable strings and raw disassembly from a binary sample.
    • Normalizes disassembly by replacing registers, immediates, and memory references with generic placeholders.
    • Stores all artefacts in a single JSON output:
        - "string_data": printable strings with frequency statistics
        - "functions": raw disassembly per function
        - "normalized_functions": abstracted/normalized disassembly
    • Generates a similarity graph of clustered samples using three similarity functions:
        - ssdeep
        - tlsh
        - sdhash
"""

import json
import re
import ssdeep
import tlsh
import html
import jc_sdhash as sd
import importlib.util
from collections import Counter
from pathlib import Path
from collections import defaultdict
from typing import Union, Tuple, Dict, Any, Callable
from types import ModuleType


# malcat import trick :)
malcat_lib: ModuleType | None = None
def import_malcat(malcat_dir: Path) -> ModuleType:
    """
    Import the Malcat shared library (.so) as a Python module.
    """
    so_files = list(malcat_dir.glob("malcat*.so"))
    if not so_files:
        raise ImportError(f"Nessun file .so di malcat trovato in {malcat_dir}")

    malcat_so = so_files[0]
    # Load the shared library as a Python module
    spec = importlib.util.spec_from_file_location("malcat", malcat_so)
    malcat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(malcat)

    print(f"[+] Malcat imported from: {malcat_so}")
    return malcat

def similarity_switch_case(all_bins: list, similarity_function: str, similarity_threshold: int):
    """
    Cluster files using a chosen similarity / fuzzy-hash function.

    Supported functions:
      - "ssdeep" (CTPH)
          * produces similarity score 0-100  
          * typical heuristic: <50 = weak; 50-80 = possible; ≳80 = likely same/variant  
          * WARNING: fuzzy-hash = heuristic — high score ≠ identical bytes; low score ≠ fully unrelated
      - "TLSH"
          * produces a **distance metric** (not percent similarity)  
          * lower distance → more similar; higher → less similar  
          * cannot assume distance=0 → exact match; distance threshold must be chosen case-by-case
      - "sdhash" (statistical features / Bloom-filter)
          * score ~0-100  
          * threshold ~21 often used in practice for strong match; for text/html maybe lower  
          * score is a **probabilistic indicator** of overlap, not "% identical"

    NOTE: all thresholds are **empirical heuristics**, derived from experiments.  
          Their reliability depends heavily on file type, size, structure, modifications, embedding, compression, etc.  
          Use fuzzy-hash results only as a **preliminary filter / clustering aid**, not as definitive proof.   
    """
    clusters = []
    if similarity_function == "ssdeep":
        clusters = cluster_by_similarity(
            files=all_bins,
            hash_func=lambda f: ssdeep.hash_from_file(str(f)),
            compare_func=ssdeep.compare,
            threshold=similarity_threshold,
            higher_is_more_similar=True,
        )
    elif similarity_function == "tlsh":
        clusters = cluster_by_similarity(
            files=all_bins,
            hash_func=lambda f: tlsh.hash(open(f, 'rb').read()),
            compare_func=tlsh.diff,  # lower = more similar
            threshold=similarity_threshold,
            higher_is_more_similar=False,
        )
    elif similarity_function == "sdhash":
        clusters = cluster_by_similarity(
            files=all_bins,
            hash_func=lambda f: sd.generate(str(f)),
            compare_func=sd.compare,
            threshold=similarity_threshold,
            higher_is_more_similar=True,
        )
    else:
        print(f"[!] Error: similarity function not supported yet!")
    return clusters

def run_pipeline(
    malcat_dir: str, 
    input_dir: str, 
    output_dir: str, 
    lcs_threshold: int, 
    similarity_function: str,
    similarity_threshold: int,
    fully_normalize: bool,
) -> Dict[str, Any]:
    """
    PROCESSING PIPELINE:
        1. Extract artefacts for each binary using Malcat
        2. Cluster binaries based on ssdeep similarity
        3. Progressive comparison of normalized functions within each cluster
        4. Store clustered results in a single JSON file
        5. Generate graph data from clustering results
    """

    malcat_dir = Path(malcat_dir).expanduser().resolve()
    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    malcat_output = output_dir / "malcat_output"
    malcat_output.mkdir(parents=True, exist_ok=True)

    print("[*] Starting MalCluster pipeline...")

    # 1. Extract artefacts for each binary using Malcat
    all_bins = []
    for bin_file in input_dir.iterdir():
        if bin_file.is_file():
            process_binary(
                bin_file,
                malcat_output,
                malcat_dir,
                fully_normalize
            )
            all_bins.append(bin_file)

    # 2. Cluster binaries based on similarity
    clusters = similarity_switch_case(all_bins, similarity_function, similarity_threshold)
    # Map JSON outputs for later comparison
    json_files = sorted(malcat_output.glob("*.json"), key=lambda f: f.stat().st_size)
    json_map = {f.stem: f for f in json_files}

    # 3. Progressive comparison of normalized functions within each cluster
    final_results = {}
    for cid, bin_list in clusters.items():
        if len(bin_list) < 2:
            continue

        json_subset = [json_map[b.stem] for b in bin_list if b.stem in json_map]

        if not json_subset:
            continue

        cmp_result = progressive_compare(
            sorted(json_subset, key=lambda f: f.stat().st_size),
            compare_results,
            lcs_threshold,
        )

        cmp_result["cluster_size"] = len(bin_list)
        cmp_result["cluster_files"] = [b.stem for b in bin_list]

        final_results[cid] = cmp_result

    # 4. Store clustered results in a single JSON file
    output_json = output_dir / "output.json"
    with open(output_json, "w", encoding="utf8") as outfile:
        json.dump(final_results, outfile, ensure_ascii=False, indent=2)

    # 5. Generate graph data from clustering results
    nodes, edges, legend_items = generate_graph(output_json)

    print("[+] Pipeline completed successfully.")
    return {"nodes":nodes, "edges":edges, "legend_items":legend_items}

# -----------------------------------------------------------
# Regexes for normalising assembly instructions
# -----------------------------------------------------------

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

def process_binary(bin_path: Path, output_dir: Path, malcat_dir: Path, fully_normalize: bool) -> None:
    """
    Process a single binary: extract strings and functions, normalize ASM, save JSON
    """
    results = {}
    base = bin_path.stem
    
    # Import Malcat if not already loaded
    global malcat_lib
    if not malcat_lib:
        malcat_lib = import_malcat(malcat_dir)
    # Analyze binary with Malcat
    analysis = malcat_lib.analyse(str(bin_path))

    # Extract printable strings and compute frequency
    strings = [str(i) for i in analysis.strings]
    results["string_data"] = {
        "strings": strings,
        "doc_freq": Counter(strings),
    }

    functions = {}
    normalized_functions = {}
    
    # Process each function
    for fn in analysis.fns:
        # Skip standard library and SEH functions
        if any(sub in str(fn) for sub in 
            ["std::", "ios_base::", "SEH.0"]
        ):
            continue

        # Extract raw disassembly lines (skip first and last lines)
        extracted_body = str(
            fn.disasm(
                use_hexadecimal=True,
                only_valid_code=False,
                use_smart_labels=False,
                resolve_symbols=False,
                resolve_functions=False,
                resolve_strings=False,
                resolve_structures=False
            )
        ).splitlines()[1:-1]

        # Clean up spacing for raw disassembly
        functions[str(fn)] = [re.sub(' +', ' ', l.strip()) for l in extracted_body]

        # Normalize assembly lines
        normalized_functions[str(fn)] = {
            "longest_common_substring": [],
            "identical": False,
            "asm": [normalize(re.sub(' +', ' ', l.strip()), fully_normalize) for l in extracted_body]
        }
    results["functions"] = functions
    results["normalized_functions"] = normalized_functions

    # Save results to JSON
    out_path = output_dir / f"{base}.json"
    with out_path.open("w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Processed {bin_path.name}")

def progressive_compare(items: list, compare_fn: Callable, lcs_threshold: int) -> dict:
    """
    Compare a list of items progressively using a comparison function.
    Items can be Paths to JSON files or already loaded dicts.
    """
    if not items:
        return None
    if len(items) == 1:
        if isinstance(items[0], Path):
            with open(items[0], "r") as f:
                return json.load(f)
        return items[0]

    # Start by comparing the first two
    result = compare_fn(items[0], items[1], lcs_threshold)

    # Compare progressively with the remaining items
    for item in items[2:]:
        result = compare_fn(result, item, lcs_threshold)

    return result

def compare_results(file1: Union[Path, dict], file2: Union[Path, dict], lcs_threshold: int):
    """
    Compare normalized functions and strings from two JSON results.
    Returns a merged dictionary with:
      - string intersection and updated doc_freq
      - normalized functions with LCS and identical flags
    """

    # Load JSON if input is Path
    file1_results = json.load(open(file1)) if isinstance(file1, Path) else file1
    file2_results = json.load(open(file2)) if isinstance(file2, Path) else file2

    results = {}
    
    # Compare strings: intersection + update document frequency
    prev_sd = file1_results["string_data"]
    new_sd  = file2_results["string_data"]
    prev_sd["doc_freq"] = Counter(prev_sd.get("doc_freq", {}))  # convert after json load
    new_sd["doc_freq"] = Counter(new_sd.get("doc_freq", {}))    # convert after json load
    intersection = set(prev_sd["strings"]) & set(new_sd["strings"])
    # DF counts how many times each string has appeared in the binaries processed so far
    prev_sd["doc_freq"].update({s: 1 for s in intersection})
    # Increment the count of binaries processed
    results["string_data"] = {
        "strings": list(intersection),
        "doc_freq": prev_sd["doc_freq"],
    }

    results["normalized_functions"] = {}
    funcs1 = file1_results.get("normalized_functions", {})
    funcs2 = file2_results.get("normalized_functions", {})

    # If one file has no functions, return the other
    if not funcs1:
        results["normalized_functions"] = funcs2
        return results
    if not funcs2:
        results["normalized_functions"] = funcs1
        return results

    # Compare functions from file1
    for name1, info1 in funcs1.items():
        best_seq = []
        identical = False

        # Check same-name function in file2
        if name1 in funcs2:
            info2 = funcs2[name1]
            if info1["asm"] == info2["asm"]:
                identical = True
                best_seq = info1["asm"][:]
            else:
                best_seq = longest_common_substring(info1["asm"], info2["asm"])

        # Compare with all other functions in file2 if not identical
        if not identical:
            for name2, info2 in funcs2.items():
                if name2 == name1:
                    continue
                seq = longest_common_substring(info1["asm"], info2["asm"])
                if len(seq) > len(best_seq):
                    best_seq = seq

        # Add to results only if LCS ≥ threshold
        if best_seq and len(best_seq) >= lcs_threshold:
            results["normalized_functions"][name1] = {
                "asm": info1["asm"][:],
                "longest_common_substring": best_seq,
                "identical": identical
            }

    # Add remaining functions from file2 not yet in results
    for name2, info2 in funcs2.items():
        if name2 in results["normalized_functions"]:
            continue

        best_seq = []
        identical = False

        # Compare with all functions from file1
        for name1, info1 in funcs1.items():
            seq = longest_common_substring(info2["asm"], info1["asm"])
            if len(seq) > len(best_seq):
                best_seq = seq

        if best_seq and len(best_seq) >= lcs_threshold:
            results["normalized_functions"][name2] = {
                "asm": info2["asm"][:],
                "longest_common_substring": best_seq,
                "identical": identical
            }

    return results

def longest_common_substring(a: list, b: list) -> list:
    """
    Compute the Longest Common Substring (LCS) between two lists of lines.
    Returns the substring (as a list) from 'a' that matches a sequence in 'b'.
    """
    n, m = len(a), len(b)
    # DP table: dp[i][j] = length of LCS ending at a[i-1] and b[j-1]
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    max_len = 0
    end_pos = 0  # end position of LCS in 'a'

    for i in range(1, n + 1):
        ai = a[i - 1]
        row = dp[i]
        prev_row = dp[i - 1]
        for j in range(1, m + 1):
            if ai == b[j - 1]:
                # Extend the previous match
                row[j] = prev_row[j - 1] + 1
                if row[j] > max_len:
                    max_len = row[j]
                    end_pos = i
            else:
                row[j] = 0

    # Return the longest common substring as a slice from 'a'
    return a[end_pos - max_len:end_pos]

def cluster_by_similarity(
    files: list, 
    hash_func: Callable, 
    compare_func: Callable, 
    threshold: int,
    higher_is_more_similar: bool,
) -> dict:
    """
    Cluster files using a generic similarity function.

    Args:
        files: list of file paths
        hash_func: function(file_path) -> hash string/object
        compare_func: function(hash1, hash2) -> similarity score (0-100)
        threshold: similarity threshold to consider files in the same cluster
        higher_is_more_similar: True if higher score = more similar (ssdeep),
                                False if lower score = more similar (tlsh)

    Returns:
        dict(cluster_id -> list of files)
    """
    clusters = defaultdict(list)  # cluster_id -> list of files
    hashes = {}  # file -> hash

    # Precompute hashes for all files
    for f in files:
        try:
            hashes[f] = hash_func(f)
        except Exception as e:
            print(f"[!] Error hashing {f}: {e}")

    cluster_id = 0  # ID for new clusters

    # Assign files to clusters
    for f in files:
        f_hash = hashes.get(f)
        if f_hash is None:
            continue  # skip files that failed hashing

        matched_any_cluster = False

        # Try to assign the file to an existing cluster
        for cid, flist in clusters.items():
            # Compute similarity between this file and all files in the cluster
            scores = [compare_func(f_hash, hashes[other]) for other in flist]
            avg_score = sum(scores) / len(scores) if scores else 0

            if (higher_is_more_similar and avg_score >= threshold) or \
               (not higher_is_more_similar and avg_score <= threshold):
                print(f"[+] Assigned file {f} to cluster with ID {cid}.")
                clusters[cid].append(f)
                matched_any_cluster = True
                break  # file assigned, no need to check other clusters

        # No cluster found → create a new one
        if not matched_any_cluster:
            clusters[cluster_id].append(f)
            cluster_id += 1

    return clusters

def generate_graph(json_path: Path) -> Tuple[str, str, str]:
    """
    Generate a graph representation of clusters and functions for visualization.
    """
    with open(json_path, "r") as f:
        clusters = json.load(f)

    nodes = []
    edges = []

    legend_colors = {}  # mapping color -> description

    # Iterate over clusters
    for cluster_id, cluster_data in clusters.items():
        cluster_size = cluster_data.get("cluster_size", 0)
        cluster_files = cluster_data.get("cluster_files", [])
        num_strings = len(cluster_data.get("string_data", {}).get("strings", []))
        num_funcs = len(cluster_data.get("normalized_functions", {}))
        num_identical = sum(1 for fn, v in cluster_data["normalized_functions"].items() if v.get("identical"))
        max_lcs = max(
            (len(v.get("longest_common_substring", [])) for v in cluster_data["normalized_functions"].values()),
            default=0
        )

        # Prepare tooltip text for cluster
        tooltip = f"""Cluster id: {cluster_id}
Cluster size: {cluster_size}
Cluster files: 
{'\n'.join(cluster_files)}
---
Strings: {num_strings}
Functions: {num_funcs}
Identical: {num_identical}
Max LCS length: {max_lcs}"""

        # Define cluster node
        cluster_color = "#FFD966"
        nodes.append({
            "id": f"cluster_{cluster_id}",
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "size": cluster_size * 5,
            "color": cluster_color,
            "font": {"color": "#ffffff"}
        })
        legend_colors[cluster_color] = "Cluster"

        # Add nodes for each function in the cluster
        for fn_name, fn_data in cluster_data["normalized_functions"].items():
            identical = fn_data.get("identical", False)
            asm_len = len(fn_data.get("asm", []))
            lcs_len = len(fn_data.get("longest_common_substring", []))
            color = "#A4C2F4" if identical else "#D9D9D9"

            # Prepare tooltip text for function
            tooltip_fn = f"""Function: {fn_name}
ASM length: {asm_len}
Identical: {identical}
LCS length: {lcs_len}"""

            fn_id = f"{cluster_id}_{fn_name}"  # unique node ID

            # Add function node
            nodes.append({
                "id": fn_id,
                "label": fn_name,
                "title": html.escape(tooltip_fn),
                "shape": "ellipse",
                "color": color
            })
            legend_colors[color] = "Identical function" if identical else "Different function"

            # Add edge from cluster node to function node
            edges.append({
                "from": f"cluster_{cluster_id}",
                "to": fn_id
            })

    # Generate HTML items for legend
    legend_items = "\n".join(
        f'<div class="legend-item"><div class="legend-color" style="background:{c}"></div>{desc}</div>'
        for c, desc in legend_colors.items()
    )

    # Return nodes/edges as JSON strings and legend as HTML
    return json.dumps(nodes), json.dumps(edges), legend_items
