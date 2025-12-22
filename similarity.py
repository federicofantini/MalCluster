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

import ssdeep
import tlsh
import jc_sdhash as sd
from collections import defaultdict
from typing import Callable

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