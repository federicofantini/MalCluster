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

import json
import re
from collections import Counter
from pathlib import Path
from typing import Union, Any, Callable

from algo import *
from capev2 import *
from graph import *
from malcat import *
from norm import *
from similarity import *


def run_pipeline(
    malcat_dir: str, 
    input_dir: str, 
    output_dir: str, 
    lcs_threshold: int, 
    similarity_function: str,
    similarity_threshold: int,
    fully_normalize: bool,
    dynamic_analysis: bool,
    capev2_base_url: str,
    capev2_api_token: str,
) -> dict[str, Any]:
    """
    PROCESSING PIPELINE:
        1. Extract artefacts for each binary using Malcat and CAPEv2
        2. Cluster binaries based on ssdeep similarity
        3. Progressive comparison of normalized functions within each cluster
        4. Store clustered results in a single JSON file
        5. Generate graph data from clustering results
    """

    malcat_dir = Path(malcat_dir).expanduser().resolve()
    input_dir = Path(input_dir).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    malcluster_output = output_dir / "malcluster_output"
    malcluster_output.mkdir(parents=True, exist_ok=True)

    print("[*] Starting pipeline...")

    # 1. Extract artefacts for each binary using Malcat and CAPEv2
    all_bins = []
    for bin_file in input_dir.iterdir():
        if bin_file.is_file():
            process_binary(
                bin_file,
                malcluster_output,
                malcat_dir,
                capev2_base_url,
                capev2_api_token,
                fully_normalize,
                dynamic_analysis,
            )
            all_bins.append(bin_file)

    # 2. Cluster binaries based on similarity
    clusters = similarity_switch_case(all_bins, similarity_function, similarity_threshold)
    # Map JSON outputs for later comparison
    json_files = sorted(malcluster_output.glob("*.json"), key=lambda f: f.stat().st_size)
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
    graph_data = generate_graph(output_json)

    print("[+] Pipeline completed successfully.")
    return graph_data

def process_binary_static_analysis(
    results: dict,
    bin_path: Path,
    malcat_dir: Path, 
    fully_normalize: bool,
):
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

    return analysis.entropy.sha256

def process_binary_dynamic_analysis(sha256_hash: str, capev2_base_url: str, capev2_api_token: str = None):
    headers = build_headers(capev2_api_token)

    tasks = search_task_by_sha256(capev2_base_url, sha256_hash, headers)
    if not tasks:
        return {}

    for task in tasks:
        task_id = task.get("id")
        if not isinstance(task_id, int):
            continue

        report = get_json_report(capev2_base_url, task_id, headers)
        if report:
            return report
    return {}

def process_binary(
    bin_path: Path, 
    output_dir: Path, 
    malcat_dir: Path,
    capev2_base_url: str,
    capev2_api_token: str,
    fully_normalize: bool,
    dynamic_analysis: bool,
) -> None:
    """
    Process a single binary: extract strings and functions, normalize ASM, save JSON
    """
    results = {}
    base = bin_path.stem
    
    print(f"[+] Static analysis...")

    sha256_bin = process_binary_static_analysis(results, bin_path, malcat_dir, fully_normalize)

    if dynamic_analysis:
        print(f"[+] Dynamic analysis...")
        report = process_binary_dynamic_analysis(sha256_bin, capev2_base_url, capev2_api_token)
        print(f"[+] Retrieved CAPEv2 report.")
        extract_data_CAPEv2(results, report)
        print(f"[+] Added CAPEv2 data to results.")

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

def load_results(file: Union[Path, dict]) -> dict:
    """Load JSON from path or return dict directly."""
    if isinstance(file, Path):
        with open(file) as f:
            return json.load(f)
    return file

def compare_strings(prev_sd: dict, new_sd: dict) -> dict:
    """Compute intersection of strings and update document frequency."""
    prev_sd = prev_sd.copy()
    new_sd = new_sd.copy()

    prev_sd["doc_freq"] = Counter(prev_sd.get("doc_freq", {}))
    new_sd["doc_freq"] = Counter(new_sd.get("doc_freq", {}))

    intersection = set(prev_sd["strings"]) & set(new_sd["strings"])
    prev_sd["doc_freq"].update({s: 1 for s in intersection})

    return {
        "strings": list(intersection),
        "doc_freq": prev_sd["doc_freq"]
    }

def compare_normalized_functions(funcs1: dict, funcs2: dict, lcs_threshold: int) -> dict:
    """Compare normalized functions and return those with LCS above threshold."""
    results = {}

    # Compare funcs from funcs1
    for name1, info1 in funcs1.items():
        best_seq = []
        identical = False

        # Same-name function
        if name1 in funcs2:
            info2 = funcs2[name1]
            if info1["asm"] == info2["asm"]:
                identical = True
                best_seq = info1["asm"][:]
            else:
                best_seq = longest_common_substring(info1["asm"], info2["asm"])

        # Compare with all other functions
        if not identical:
            for name2, info2 in funcs2.items():
                if name2 == name1:
                    continue
                seq = longest_common_substring(info1["asm"], info2["asm"])
                if len(seq) > len(best_seq):
                    best_seq = seq

        if best_seq and len(best_seq) >= lcs_threshold:
            results[name1] = {
                "asm": info1["asm"][:],
                "longest_common_substring": best_seq,
                "identical": identical
            }

    # Add remaining funcs from funcs2
    for name2, info2 in funcs2.items():
        if name2 in results:
            continue
        best_seq = []
        identical = False
        for name1, info1 in funcs1.items():
            seq = longest_common_substring(info2["asm"], info1["asm"])
            if len(seq) > len(best_seq):
                best_seq = seq

        if best_seq and len(best_seq) >= lcs_threshold:
            results[name2] = {
                "asm": info2["asm"][:],
                "longest_common_substring": best_seq,
                "identical": identical
            }

    return results

def compare_behavior_summary(bs1: dict, bs2: dict) -> dict:
    """
    Compare two behavior summaries.
    For keys present in both dicts, take intersection of values.
    For keys present in only one dict, keep the values as is.
    Returns a dict with lists as values.
    """
    result = {}

    all_keys = set(bs1.keys()) | set(bs2.keys())

    for key in all_keys:
        vals1 = set(bs1.get(key, []))
        vals2 = set(bs2.get(key, []))

        if key in bs1 and key in bs2:
            # Intersection
            result[key] = list(vals1 & vals2)
        elif key in bs1:
            result[key] = list(vals1)
        else:
            result[key] = list(vals2)

    return result

def normalize_counter(counts: dict) -> dict:
    """Convert a counter (feature -> count) into a probability distribution."""
    total = 0.0
    for v in counts.values():
        if v > 0:
            total += float(v)
    if total <= 0.0:
        return {}
    return {k: float(v) / total for k, v in counts.items() if v > 0}

def safe_count(counts: dict, key: str) -> float:
    """Read a non-negative count for a key from a dict-like counter."""
    v = counts.get(key, 0)
    try:
        v = float(v)
    except Exception:
        v = 0.0
    return max(0.0, v)

def merge_feature_sets(
    set_a: set,
    set_b: set,
    counts_a: dict,
    counts_b: dict,
    jaccard_value: float,
    jaccard_low: float,
    jaccard_high: float,
    rare_count_min: float,
    rare_fraction_min: float,
) -> set:
    """
    Decide which features to keep in the merged set:
    - if jaccard is low: keep only intersection (or empty if intersection is empty).
    - if jaccard is medium: keep intersection.
    - if jaccard is high: keep intersection + rare-but-strong uniques (by counts).
    """
    common = set_a & set_b

    # Return null if low overlap
    if jaccard_value <= jaccard_low:
        return set()

    # Conservative when overlap is not strong
    if jaccard_value < jaccard_high:
        return common

    # High overlap: allow some uniques, but only if they are "strong" by counts
    merged = set(common)

    # Reference mass to measure "fraction of core"
    core_mass = 0.0
    for k in common:
        core_mass += safe_count(counts_a, k) + safe_count(counts_b, k)
    if core_mass <= 0.0:
        core_mass = 1.0

    uniques = (set_a | set_b) - common
    for k in uniques:
        c = safe_count(counts_a, k) + safe_count(counts_b, k)

        # keep if it is large in absolute terms OR not negligible vs the core
        if c >= rare_count_min or (c / core_mass) >= rare_fraction_min:
            merged.add(k)

    return merged

def merge_counters(
    counts_a: dict,
    counts_b: dict,
    keep_keys: set,
    hellinger_value: float,
    hellinger_low: float,
) -> Counter:
    """
    Merge counters coherently:
    - if distributions are similar (H <= hellinger_low): aggregate freely (mean)
    - otherwise: keep only "core counts" (min over intersection, 0 for non-common keys).
    """
    out = Counter()
    if not keep_keys:
        return out

    if hellinger_value <= hellinger_low:
        for k in keep_keys:
            v = safe_count(counts_a, k) + safe_count(counts_b, k)
            v /= 2.0  # mean
            v = int(round(v))
            if v > 0:
                out[k] = v
        return out

    # Conservative: only keep counts for keys present in both, using min()
    for k in keep_keys:
        if k in counts_a and k in counts_b:
            v = min(safe_count(counts_a, k), safe_count(counts_b, k))
            v = int(v)
            if v > 0:
                out[k] = v

    return out

def compare_jaccard_hellinger(
    a: dict,
    b: dict,
    jaccard_low: float = 0.10,
    jaccard_high: float = 0.40,
    hellinger_low: float = 0.25,
    hellinger_high: float = 0.60,
    rare_count_min: float = 1.0,
    rare_fraction_min: float = 0.20,
):
    """
    Merge two profiles into one representative profile: 
    - if BOTH names and categories overlaps are very low, OR both 
      distributions are very different, output is NULL (empty lists + empty counters). 
    - otherwise: 
      * sets: intersection when overlap is not strong, else intersection + strong uniques 
      * counters: sum/mean if distributions are similar, else conservative min on common keys
    """

    # Safety: missing or malformed input
    if not isinstance(a, dict) or not isinstance(b, dict):
        return {"names": [], "categories": [], "name_counter": {}, "category_counter": {}}

    names_a = a.get("names", [])
    cats_a = a.get("categories", [])
    name_counts_a = a.get("name_counter", {})
    cat_counts_a = a.get("category_counter", {})

    names_b = b.get("names", [])
    cats_b = b.get("categories", [])
    name_counts_b = b.get("name_counter", {})
    cat_counts_b = b.get("category_counter", {})

    set_names_a = set(names_a)
    set_names_b = set(names_b)
    set_cats_a = set(cats_a)
    set_cats_b = set(cats_b)

    # Jaccard overlap
    names_j = jaccard_similarity(set_names_a, set_names_b)
    cats_j = jaccard_similarity(set_cats_a, set_cats_b)

    # Normalize before Hellinger
    p_name_a = normalize_counter(name_counts_a)
    p_name_b = normalize_counter(name_counts_b)
    p_cat_a = normalize_counter(cat_counts_a)
    p_cat_b = normalize_counter(cat_counts_b)

    names_h = hellinger_distance(p_name_a, p_name_b)
    cats_h = hellinger_distance(p_cat_a, p_cat_b)

    # Reject completely incompatible profiles
    very_low_overlap = (names_j < jaccard_low) and (cats_j < jaccard_low)
    very_diff_distributions = (
        (names_h > hellinger_high)
        and (cats_h > hellinger_high)
        and (names_j < jaccard_high)
        and (cats_j < jaccard_high)
    )

    if very_low_overlap or very_diff_distributions:
        return {"names": [], "categories": [], "name_counter": {}, "category_counter": {}}

    # Merge feature sets
    merged_name_set = merge_feature_sets(
        set_names_a, set_names_b,
        name_counts_a, name_counts_b,
        names_j, jaccard_low, jaccard_high,
        rare_count_min, rare_fraction_min,
    )

    merged_cat_set = merge_feature_sets(
        set_cats_a, set_cats_b,
        cat_counts_a, cat_counts_b,
        cats_j, jaccard_low, jaccard_high,
        rare_count_min, rare_fraction_min,
    )

    # Merge counters
    merged_name_counter = merge_counters(
        name_counts_a, name_counts_b,
        merged_name_set, names_h, hellinger_low,
    )

    merged_cat_counter = merge_counters(
        cat_counts_a, cat_counts_b,
        merged_cat_set, cats_h, hellinger_low,
    )

    return {
        "names": sorted(merged_name_set),
        "categories": sorted(merged_cat_set),
        "name_counter": dict(merged_name_counter),
        "category_counter": dict(merged_cat_counter),
    }

def compare_results(file1: Union[Path, dict], file2: Union[Path, dict], lcs_threshold: int) -> dict:
    """Main comparison function."""
    file1_results = load_results(file1)
    file2_results = load_results(file2)

    results = {}

    # Compare strings
    results["string_data"] = compare_strings(
        file1_results["string_data"],
        file2_results["string_data"]
    )

    # Compare normalized functions
    results["normalized_functions"] = compare_normalized_functions(
        file1_results.get("normalized_functions", {}),
        file2_results.get("normalized_functions", {}),
        lcs_threshold,
    )

    # Compare behavior summary
    results["behavior_summary"] = compare_behavior_summary(
        file1_results.get("behavior_summary", {}),
        file2_results.get("behavior_summary", {}),
    )

    # Compare signatures
    results["signatures"] = compare_jaccard_hellinger(
        file1_results.get("signatures", {}),
        file2_results.get("signatures", {}),
    )

    # Compare apicall
    results["api"] = compare_jaccard_hellinger(
        file1_results.get("api", {}),
        file2_results.get("api", {}),
    )

    return results
