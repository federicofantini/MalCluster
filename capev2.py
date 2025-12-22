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


import requests
from collections import Counter
from norm import normalize_windows_user_path

def build_headers(api_token: str | None):
    """Return headers with optional Authorization token."""
    headers = {}
    if api_token:
        headers["Authorization"] = f"Token {api_token}"
    return headers

def search_task_by_sha256(base_url: str, sha256_hash: str, headers: dict):
    """Search CAPEv2 tasks by SHA256; returns list or empty list."""
    try:
        url = f"{base_url.rstrip('/')}/apiv2/tasks/search/sha256/{sha256_hash}/"
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        return response.json().get("data", [])
    except requests.RequestException:
        return []


def get_json_report(base_url: str, task_id: int, headers: dict):
    """Get JSON report for task ID; returns dict or empty dict."""
    try:
        url = f"{base_url.rstrip('/')}/apiv2/tasks/get/report/{task_id}/json/"
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        return response.json() or {}
    except requests.RequestException:
        return {}

def extract_signatures(report):
    sig_names = set()
    sig_categories = set()
    sig_name_counter = Counter()
    sig_category_counter = Counter()

    for s in report.get("signatures", []):
        name = s.get("name")
        if name:
            sig_names.add(name)
            sig_name_counter[name] += 1

        for c in s.get("categories", []):
            sig_categories.add(c)
            sig_category_counter[c] += 1

    return list(sig_names), list(sig_categories), sig_name_counter, sig_category_counter

def extract_behavior_summary(report):
    summary = report.get("behavior", {}).get("summary", {})

    behavior_data = {}

    for key, value in summary.items():
        if isinstance(value, list):
            if "file" in key.lower():
                norm_list = [
                    normalize_windows_user_path(v)
                    for v in value
                    if isinstance(v, str)
                ]
                behavior_data[key] = list(set(norm_list))
            else:
                behavior_data[key] = list(set(value))

    return behavior_data

def extract_dropped(report):
    dropped = {
        "tlsh": set(),
        "ssdeep": set(),
        "yara": set(),
        "cape_yara": set(),
    }

    for d in report.get("dropped", []):
        tlsh = d.get("tlsh")
        if tlsh:
            dropped["tlsh"].add(tlsh)

        ssdeep = d.get("ssdeep")
        if ssdeep:
            dropped["ssdeep"].add(ssdeep)

        for y in d.get("yara", []):
            name = y.get("name")
            if name:
                dropped["yara"].add(name)

        for y in d.get("cape_yara", []):
            name = y.get("name")
            if name:
                dropped["cape_yara"].add(name)

    return {k: list(v) for k, v in dropped.items()}

def extract_api_counts(report):
    api_names = set()
    api_categories = set()
    api_name_counter = Counter()
    api_category_counter = Counter()

    for proc in report.get("behavior", {}).get("processes", []):
        for call in proc.get("calls", []):
            api = call.get("api")
            if api:
                api_names.add(api)
                api_name_counter[api] += 1

            category = call.get("category")
            if category:
                api_categories.add(category)
                api_category_counter[category] += 1

    return (
        list(api_names),
        list(api_categories),
        api_name_counter,
        api_category_counter,
    )

def extract_data_CAPEv2(results: dict, report: dict):
    # signatures
    sig_names, sig_categories, sig_name_counter, sig_category_counter = extract_signatures(report)

    results["signatures"] = {
        "names": sig_names,
        "categories": sig_categories,
        "name_counter": dict(sig_name_counter),
        "category_counter": dict(sig_category_counter),
    }

    # behavior summary
    behavior_summary = extract_behavior_summary(report)
    for k, v in behavior_summary.items():
        if isinstance(v, set):
            behavior_summary[k] = list(v)
    results["behavior_summary"] = behavior_summary

    # dropped files
    results["dropped"] = extract_dropped(report)

    # api calls
    api_names, api_categories, api_name_counter, api_category_counter = extract_api_counts(report)

    results["api"] = {
        "names": api_names,
        "categories": api_categories,
        "name_counter": dict(api_name_counter),
        "category_counter": dict(api_category_counter),
    }

    return results