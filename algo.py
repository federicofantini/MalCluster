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


import math

def jaccard_similarity(set1: set, set2: set) -> float:
    """
    Compute Jaccard similarity between two sets.
    Returns a float between 0 and 1.
    """
    if not set1 and not set2:
        return 1.0  # both empty → max similarity
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union else 0.0

def hellinger_distance(counter1: dict, counter2: dict) -> float:
    """
    Compute the Hellinger distance between two discrete distributions
    given by counters. Returns a float between 0 and 1.
    """
    # Get the union of all keys
    all_keys = set(counter1) | set(counter2)
    
    # Total counts
    total1 = sum(counter1.values())
    total2 = sum(counter2.values())
    if total1 == 0 or total2 == 0:
        # One distribution is empty → max distance
        return 1.0

    # Compute Hellinger sum
    sum_sq = 0.0
    for k in all_keys:
        p = counter1.get(k, 0) / total1
        q = counter2.get(k, 0) / total2
        sum_sq += (math.sqrt(p) - math.sqrt(q)) ** 2

    return (math.sqrt(sum_sq) / math.sqrt(2))

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