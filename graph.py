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

import html
import json
from pathlib import Path
from typing import Tuple

def legend_html(color_to_label: dict) -> str:
    """
    Build legend HTML from a {color: label} map.
    """
    return "\n".join(
        f'<div class="legend-item"><div class="legend-color" style="background:{color}"></div>{label}</div>'
        for color, label in (color_to_label or {}).items()
    )

def generate_graph(json_path: Path) -> dict:
    """
    Generate graph datasets and return template-ready data.
    """
    with open(json_path, "r", encoding="utf8") as f:
        clusters = json.load(f)

    # Strings
    nodes_strings, edges_strings, legend_strings = graph_strings(clusters)
    strings = {
        "nodes": nodes_strings,
        "edges": edges_strings,
        "legend_items": legend_html(legend_strings) if legend_strings else "",
    }

    # Functions
    nodes_functions, edges_functions, legend_functions = graph_functions(clusters)
    functions = {
        "nodes": nodes_functions,
        "edges": edges_functions,
        "legend_items": legend_html(legend_functions),
    }

    # Signatures
    n_s_names, e_s_names, l_s_names = graph_signatures(clusters, view="names")
    n_s_cats,  e_s_cats,  l_s_cats  = graph_signatures(clusters, view="categories")
    signatures = {
        "names": {
            "nodes": n_s_names,
            "edges": e_s_names,
            "legend_items": legend_html(l_s_names),
        },
        "categories": {
            "nodes": n_s_cats,
            "edges": e_s_cats,
            "legend_items": legend_html(l_s_cats),
        },
    }

    # Behavior summary
    behavior_summary = graph_behavior(clusters)
    
    # Dropped
    n_d, e_d, l_d = graph_dropped(clusters)
    dropped = {
        "nodes": n_d,
        "edges": e_d,
        "legend_items": legend_html(l_d) if l_d else "",
    }

    # API
    n_a_names, e_a_names, l_a_names = graph_api(clusters, view="names")
    n_a_cats,  e_a_cats,  l_a_cats  = graph_api(clusters, view="categories")
    api = {
        "names": {
            "nodes": n_a_names,
            "edges": e_a_names,
            "legend_items": legend_html(l_a_names),
        },
        "categories": {
            "nodes": n_a_cats,
            "edges": e_a_cats,
            "legend_items": legend_html(l_a_cats),
        },
    }

    return {
        "strings": strings,
        "functions": functions,
        "signatures": signatures,
        "behavior_summary": behavior_summary,
        "dropped": dropped,
        "api": api,
    }


def graph_strings(clusters: dict) -> Tuple[list, list, dict]:
    """
    Build nodes/edges/legend for printable strings.
    """

    nodes: list = []
    edges: list = []
    legend_colors: dict = {}

    cluster_color = "#FFD966"
    string_color = "#A7F3D0"

    legend_colors[cluster_color] = "Cluster"
    legend_colors[string_color] = "String"

    for cluster_id, cluster_data in (clusters or {}).items():
        cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
        cluster_files = cluster_data.get("cluster_files", []) or []
        doc_freq = cluster_data.get("string_data", {}).get("doc_freq", {}) or {}

        cluster_node_id = f"cluster_{cluster_id}"
        tooltip = (
            f"Cluster id: {cluster_id}\n"
            f"Cluster size: {cluster_size}\n"
            f"Cluster files:\n" + "\n".join(cluster_files)
        )

        # Cluster node
        nodes.append({
            "id": cluster_node_id,
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "value": max(1, cluster_size),
            "color": cluster_color,
            "font": {"color": "#ffffff"},
        })

    # String nodes (doc_freq)
    for i, (s, count) in enumerate(doc_freq.items()):
        s = str(s)
        count = int(count or 1)

        node_id = f"{cluster_id}str{i}"
        label = s if len(s) <= 60 else (s[:57] + "…")

        nodes.append({
            "id": node_id,
            "label": label,
            "title": html.escape(f"String: {s}\nDoc freq: {count}"),
            "shape": "dot",
            "value": max(1, count),
            "color": string_color,
        })

        edges.append({
            "from": cluster_node_id,
            "to": node_id
        })

    return nodes, edges, legend_colors

def graph_functions(clusters: dict) -> Tuple[list, list, dict]:
    """
    Build nodes/edges/legend for normalized functions.
    Keeps the current "cluster -> function" structure and highlights identical functions.
    """
    nodes: list = []
    edges: list = []
    legend_colors: dict = {}

    cluster_color = "#FFD966"
    identical_color = "#A4C2F4"
    different_color = "#D9D9D9"

    legend_colors[cluster_color] = "Cluster"
    legend_colors[identical_color] = "Identical function"
    legend_colors[different_color] = "Different function"

    for cluster_id, cluster_data in (clusters or {}).items():
        cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
        cluster_files = cluster_data.get("cluster_files", []) or []
        functions = cluster_data.get("normalized_functions", {}) or {}

        cluster_node_id = f"cluster_{cluster_id}"

        tooltip = (
            f"Cluster id: {cluster_id}\n"
            f"Cluster size: {cluster_size}\n"
            f"Cluster files:\n" + "\n".join(cluster_files)
        )

        # Use "value" so node weight works consistently with vis-network scaling
        nodes.append({
            "id": cluster_node_id,
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "value": max(1, cluster_size),
            "color": cluster_color,
            "font": {"color": "#ffffff"},
        })

        for fn_name, fn_data in functions.items():
            identical = bool(fn_data.get("identical", False))
            asm_len = len(fn_data.get("asm", []) or [])
            lcs_len = len(fn_data.get("longest_common_substring", []) or [])

            fn_id = f"{cluster_id}_{fn_name}"
            color = identical_color if identical else different_color

            tooltip_fn = (
                f"Function: {fn_name}\n"
                f"ASM length: {asm_len}\n"
                f"Identical: {identical}\n"
                f"LCS length: {lcs_len}"
            )

            nodes.append({
                "id": fn_id,
                "label": fn_name,
                "title": html.escape(tooltip_fn),
                "shape": "dot",
                "value": max(1, lcs_len),
                "color": color,
            })

            edges.append({"from": cluster_node_id, "to": fn_id})

    return nodes, edges, legend_colors

def graph_signatures(clusters: dict, view: str = "names") -> Tuple[list, list, dict]:
    """
    Signatures graph.

    view="names"      -> Cluster -> signature names (node size weighted by count)
    view="categories" -> Cluster -> signature categories (node size weighted by count)
    """
    nodes: list = []
    edges: list = []
    legend_colors: dict = {}

    cluster_color = "#FFD966"
    name_color = "#FF9999"
    category_color = "#FF6666"

    legend_colors[cluster_color] = "Cluster"
    if view == "names":
        legend_colors[name_color] = "Signature name"
    elif view == "categories":
        legend_colors[category_color] = "Signature category"
    else:
        raise ValueError("view must be 'names' or 'categories'")

    for cluster_id, cluster_data in (clusters or {}).items():
        cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
        cluster_files = cluster_data.get("cluster_files", []) or []

        signatures = cluster_data.get("signatures", {}) or {}
        names = signatures.get("names", []) or []
        categories = signatures.get("categories", []) or []
        name_counter = signatures.get("name_counter", {}) or {}
        category_counter = signatures.get("category_counter", {}) or {}

        cluster_node_id = f"cluster_{cluster_id}"
        tooltip = (
            f"Cluster id: {cluster_id}\n"
            f"Cluster size: {cluster_size}\n"
            f"Cluster files:\n" + "\n".join(cluster_files)
        )

        # Use "value" (not "size") so vis-network scaling works consistently
        nodes.append({
            "id": cluster_node_id,
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "value": max(1, cluster_size),
            "color": cluster_color,
            "font": {"color": "#ffffff"},
        })

        if view == "names":
            for name in names:
                count = int(name_counter.get(name, 1) or 1)
                node_id = f"{cluster_id}_sig_{name}"
                nodes.append({
                    "id": node_id,
                    "label": name,
                    "title": html.escape(f"Signature name: {name}\nCount: {count}"),
                    "shape": "dot",
                    "value": max(1, count),
                    "color": name_color,
                })
                edges.append({"from": cluster_node_id, "to": node_id})

        if view == "categories":
            for cat in categories:
                count = int(category_counter.get(cat, 1) or 1)
                node_id = f"{cluster_id}_sigcat_{cat}"
                nodes.append({
                    "id": node_id,
                    "label": cat,
                    "title": html.escape(f"Signature category: {cat}\nCount: {count}"),
                    "shape": "dot",
                    "value": max(1, count),
                    "color": category_color,
                })
                edges.append({"from": cluster_node_id, "to": node_id})

    return nodes, edges, legend_colors

def graph_api(clusters: dict, view: str = "names") -> Tuple[list, list, dict]:
    """
    API graph.

    view="names"      -> Cluster -> API names (node size weighted by count)
    view="categories" -> Cluster -> API categories (node size weighted by count)
    """
    nodes: list = []
    edges: list = []
    legend_colors: dict = {}

    cluster_color = "#FFD966"
    name_color = "#9999FF"
    category_color = "#6666FF"

    legend_colors[cluster_color] = "Cluster"
    if view == "names":
        legend_colors[name_color] = "API name"
    elif view == "categories":
        legend_colors[category_color] = "API category"
    else:
        raise ValueError("view must be 'names' or 'categories'")

    for cluster_id, cluster_data in (clusters or {}).items():
        cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
        cluster_files = cluster_data.get("cluster_files", []) or []

        api_data = cluster_data.get("api", {}) or {}
        names = api_data.get("names", []) or []
        categories = api_data.get("categories", []) or []
        name_counter = api_data.get("name_counter", {}) or {}
        category_counter = api_data.get("category_counter", {}) or {}

        cluster_node_id = f"cluster_{cluster_id}"
        tooltip = (
            f"Cluster id: {cluster_id}\n"
            f"Cluster size: {cluster_size}\n"
            f"Cluster files:\n" + "\n".join(cluster_files)
        )

        nodes.append({
            "id": cluster_node_id,
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "value": max(1, cluster_size),
            "color": cluster_color,
            "font": {"color": "#ffffff"},
        })

        if view == "names":
            for name in names:
                count = int(name_counter.get(name, 1) or 1)
                node_id = f"{cluster_id}_api_{name}"
                nodes.append({
                    "id": node_id,
                    "label": name,
                    "title": html.escape(f"API name: {name}\nCount: {count}"),
                    "shape": "dot",
                    "value": max(1, count),
                    "color": name_color,
                })
                edges.append({"from": cluster_node_id, "to": node_id})

        if view == "categories":
            for cat in categories:
                count = int(category_counter.get(cat, 1) or 1)
                node_id = f"{cluster_id}_apicat_{cat}"
                nodes.append({
                    "id": node_id,
                    "label": cat,
                    "title": html.escape(f"API category: {cat}\nCount: {count}"),
                    "shape": "dot",
                    "value": max(1, count),
                    "color": category_color,
                })
                edges.append({"from": cluster_node_id, "to": node_id})

    return nodes, edges, legend_colors

def graph_behavior(clusters: dict) -> dict:
    """
    Behavior summary graph datasets.
    """
    # Section colors
    section_colors = {
        "files": "#1ABC9C",
        "read_files": "#3498DB",
        "write_files": "#2ECC71",
        "delete_files": "#E74C3C",
        "keys": "#9B59B6",
        "read_keys": "#8E44AD",
        "write_keys": "#F39C12",
        "delete_keys": "#D35400",
        "executed_commands": "#34495E",
        "resolved_apis": "#16A085",
        "mutexes": "#E84393",
        "created_services": "#F1C40F",
        "started_services": "#95A5A6",
    }
    default_section_color = "#C9DAF8"
    cluster_color = "#FFD966"

    # Collect all sections across clusters
    all_sections = set()
    for _, cluster_data in (clusters or {}).items():
        behavior = cluster_data.get("behavior_summary", {}) or {}
        for section in behavior.keys():
            all_sections.add(section)

    sections = sorted(all_sections)

    def build_one_section(section: str) -> tuple[list, list, dict]:
        nodes: list = []
        edges: list = []
        legend_colors: dict = {}

        legend_colors[cluster_color] = "Cluster"

        sec_color = section_colors.get(section, default_section_color)
        legend_colors[sec_color] = f"Behavior section: {section}"

        for cluster_id, cluster_data in (clusters or {}).items():
            cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
            cluster_files = cluster_data.get("cluster_files", []) or []
            behavior = cluster_data.get("behavior_summary", {}) or {}
            actions = behavior.get(section, []) or []

            cluster_node_id = f"cluster_{cluster_id}"
            tooltip = (
                f"Cluster id: {cluster_id}"
                f"Cluster size: {cluster_size}"
                f"Cluster files: " + "".join(cluster_files)
            )

            nodes.append({
                "id": cluster_node_id,
                "label": f"Cluster {cluster_id}",
                "title": html.escape(tooltip),
                "shape": "dot",
                "value": max(1, cluster_size),
                "color": cluster_color,
                "font": {"color": "#ffffff"},
            })

            for i, action in enumerate(actions):
                action_id = f"{cluster_id}_beh_{section}_{i}"
                nodes.append({
                    "id": action_id,
                    "label": str(action),
                    "title": html.escape(f"{section}: {action}"),
                    "shape": "dot",
                    "color": sec_color,
                })
                edges.append({"from": cluster_node_id, "to": action_id})

        return nodes, edges, legend_colors

    data = {}
    for section in sections:
        n, e, leg = build_one_section(section)
        data[section] = {
            "nodes": n,
            "edges": e,
            "legend_items": legend_html(leg),
        }

    return {"sections": sections, "data": data}

def graph_dropped(clusters: dict) -> Tuple[list, list, dict]:
    """Dropped files graph (filenames only)."""
    nodes: list = []
    edges: list = []
    legend_colors: dict = {}

    cluster_color = "#FFD966"
    dropped_color = "#FFCC99"
    legend_colors[cluster_color] = "Cluster"
    legend_colors[dropped_color] = "Dropped file"

    for cluster_id, cluster_data in (clusters or {}).items():
        cluster_size = int(cluster_data.get("cluster_size", 0) or 0)
        cluster_files = cluster_data.get("cluster_files", []) or []

        dropped_data = cluster_data.get("dropped", {}) or {}
        files = dropped_data.get("files", []) or dropped_data.get("names", []) or []

        cluster_node_id = f"cluster_{cluster_id}"
        tooltip = (
            f"Cluster id: {cluster_id}\n"
            f"Cluster size: {cluster_size}\n"
            f"Cluster files:\n" + "\n".join(cluster_files)
        )

        nodes.append({
            "id": cluster_node_id,
            "label": f"Cluster {cluster_id}",
            "title": html.escape(tooltip),
            "shape": "dot",
            "value": max(1, cluster_size),
            "color": cluster_color,
            "font": {"color": "#ffffff"},
        })

        for i, fname in enumerate(files):
            node_id = f"{cluster_id}_dropped_{i}"
            nodes.append({
                "id": node_id,
                "label": str(fname),
                "title": html.escape(f"Dropped file: {fname}"),
                "shape": "dot",
                "color": dropped_color,
            })
            edges.append({"from": cluster_node_id, "to": node_id})

    return nodes, edges, legend_colors