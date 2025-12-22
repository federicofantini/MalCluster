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


import os
from flask import Flask, render_template, request, render_template_string, flash
from werkzeug.utils import secure_filename
from malcluster import run_pipeline

app = Flask(__name__)
app.secret_key = "change_me"

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>MalCluster</title>

<link rel="stylesheet" href="https://unpkg.com/vis-network/styles/vis-network.css" />
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>

<style>
  body { font-family: Arial, sans-serif; margin: 0; background-color: #0d1117; color: #c9d1d9; }

  /* Left sidebar */
  #sidebar {
    position: fixed;
    top: 0; left: 0;
    width: 380px;
    height: 100vh;
    background: rgba(13,17,23,0.98);
    border-right: 1px solid #30363d;
    padding: 14px 12px;
    z-index: 10000; /* above canvas */
    box-sizing: border-box;
    overflow: auto;
  }

  #sidebar h3 {
    margin: 0 0 10px 0;
    font-size: 14px;
    color: #c9d1d9;
  }

  .sideSection { margin-bottom: 14px; }
  .sideLabel { font-size: 12px; opacity: 0.9; margin: 10px 0 6px; }

  .sideBtn {
    width: 100%;
    text-align: left;
    padding: 10px 10px;
    border-radius: 8px;
    border: 1px solid #30363d;
    background: #0d1117;
    color: #c9d1d9;
    cursor: pointer;
    margin-bottom: 8px;
    font-size: 13px;
  }
  .sideBtn:hover { border-color: #58a6ff; }
  .sideBtn.active {
    border-color: #58a6ff;
    box-shadow: 0 0 0 1px rgba(88,166,255,0.35) inset;
  }

  /* Toggle row for signatures/api */
  #toggleRow { display: none; margin-top: 6px; }
  #toggleRowInner { display:flex; gap:8px; }
  .miniToggle {
    width: 50%;
    padding: 8px 10px;
    border-radius: 999px;
    border: 1px solid #30363d;
    background: #0d1117;
    color: #c9d1d9;
    cursor: pointer;
    font-size: 12px;
  }
  .miniToggle.active {
    border-color: #58a6ff;
    box-shadow: 0 0 0 1px rgba(88,166,255,0.35) inset;
  }

  /* Behavior sections */
  #behaviorRow { display: none; margin-top: 10px; }
  #behaviorButtons {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
    max-height: 300px;
    overflow: auto;
    border: 1px solid #30363d;
    padding: 8px;
    border-radius: 10px;
  }
  .miniBtn {
    padding: 6px 10px;
    border-radius: 999px;
    border: 1px solid #30363d;
    background: #0d1117;
    color: #c9d1d9;
    cursor: pointer;
    font-size: 12px;
    white-space: nowrap;
  }
  .miniBtn.active {
    border-color: #58a6ff;
    box-shadow: 0 0 0 1px rgba(88,166,255,0.35) inset;
  }

  /* Graph canvas to the right of sidebar */
  #graph {
    position: fixed;
    top: 0;
    left: 260px;
    width: calc(100vw - 260px);
    height: 100vh;
    z-index: 1;
  }

  /* Legend on the right */
  #legend {
    position: fixed;
    top: 10px;
    right: 10px;
    width: 260px;
    background: rgba(255,255,255,0.92);
    color: #111;
    border: 1px solid #ccc;
    padding: 10px;
    border-radius: 6px;
    font-size: 12px;
    max-height: 70vh;
    overflow: auto;
    z-index: 9000;
  }
  .legend-item { display: flex; align-items: center; margin-bottom: 6px; }
  .legend-color { width: 14px; height: 14px; margin-right: 6px; border-radius: 50%; }

  /* Loading overlay */
  #loadingOverlay {
    position: fixed; inset: 0;
    background: rgba(0,0,0,0.55);
    display: none; align-items: center; justify-content: center;
    z-index: 20000;
  }
  #loadingBox {
    width: 360px;
    background: rgba(13,17,23,0.95);
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px;
    box-sizing: border-box;
  }
  #loadingHeader {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap: 10px;
    margin-bottom: 10px;
  }
  #loadingText { font-size: 14px; color: #c9d1d9; }
  #cancelGraphBtn {
    background: none;
    border: none;
    color: #c9d1d9;
    font-size: 18px;
    cursor: pointer;
    line-height: 1;
  }
  #loadingBarWrap { width: 100%; height: 10px; background: #30363d; border-radius: 6px; overflow: hidden; }
  #loadingBar { width: 0%; height: 100%; background: #58a6ff; }

  /* Help box */
  #helpSection .helpBox{
    border: 1px solid #30363d;
    background: rgba(22,27,34,0.7);
    border-radius: 10px;
    padding: 10px;
    font-size: 12px;
    line-height: 1.35;
  }
  #helpSection .helpTitle{
    font-weight: 700;
    margin-bottom: 6px;
    color: #c9d1d9;
  }
  #helpSection .helpText code{
    background: rgba(110,118,129,0.25);
    padding: 1px 6px;
    border-radius: 6px;
  }
  #helpSection ul{
    margin: 6px 0 0 18px;
    padding: 0;
  }
  #helpSection li{ margin: 3px 0; }

</style>
</head>

<body>
  <div id="sidebar">
    <h3>Datasets</h3>

    <div class="sideSection">
      <button class="sideBtn" data-dataset="strings" id="btn_strings">strings</button>
      <button class="sideBtn" data-dataset="functions" id="btn_functions">functions</button>
      <button class="sideBtn" data-dataset="signatures" id="btn_signatures">signatures</button>
      <button class="sideBtn" data-dataset="behavior_summary" id="btn_behavior">behavior_summary</button>
      <button class="sideBtn" data-dataset="dropped" id="btn_dropped">dropped</button>
      <button class="sideBtn" data-dataset="api" id="btn_api">apicalls</button>
    </div>

    <div class="sideSection" id="toggleRow">
      <div class="sideLabel">View</div>
      <div id="toggleRowInner">
        <button class="miniToggle" id="toggleNames">names</button>
        <button class="miniToggle" id="toggleCategories">categories</button>
      </div>
    </div>

    <div class="sideSection" id="behaviorRow">
      <div class="sideLabel">Behavior sections</div>
      <div id="behaviorButtons"></div>
    </div>

    <div class="sideSection" id="helpSection">
      <div class="sideLabel">Help</div>
      <div class="helpBox">
        <div class="helpTitle">What am I looking at?</div>
        <div class="helpText">
          <b>Clustering</b> groups samples using fuzzy-hash similarity (<code>ssdeep</code>, <code>TLSH</code>, or <code>sdhash</code>).<br/><br/>
          <b>Static analysis</b> comes from Malcat: strings + per-function disassembly. Disassembly is normalized by abstracting
          registers/immediates/memory to placeholders (optional full normalization).<br/><br/>
          <b>Dynamic analysis</b> comes from CAPEv2: signatures, behavior summary, dropped files and apicalls.<br/><br/>
          <b>Progressive compare</b> works inside each cluster: results are merged pairwise, keeping the <i>core</i> shared artefacts across the whole cluster:
          <ul>
            <li><b>Strings:</b> set intersection + document-frequency counter.</li>
            <li><b>Functions:</b> Longest Common Substring (LCS) on normalized ASM lines (kept if LCS ≥ threshold), with "identical" flag when exact match.</li>
            <li><b>Behavior summary:</b> Work in progress...</li>
            <li><b>Signatures & API calls:</b> merged using Jaccard overlap + Hellinger distance on counts.</li>
          </ul>
          Use the left buttons to switch dataset; some datasets offer <i>names</i>/<i>categories</i> views.
        </div>
      </div>
    </div>

  </div>

  <div id="graph"></div>
  <div id="legend"></div>

  <div id="loadingOverlay">
    <div id="loadingBox">
      <div id="loadingHeader">
        <div id="loadingText">Generating graph…</div>
        <button id="cancelGraphBtn" title="Cancel">✕</button>
      </div>
      <div id="loadingBarWrap"><div id="loadingBar"></div></div>
    </div>
  </div>

<script>
/* Data injected by Jinja */
var datasets = {
  strings: {
    nodes: {{ strings.nodes | tojson }},
    edges: {{ strings.edges | tojson }},
    legend: {{ strings.legend_items | tojson }}
  },
  functions: {
    nodes: {{ functions.nodes | tojson }},
    edges: {{ functions.edges | tojson }},
    legend: {{ functions.legend_items | tojson }}
  },
  signatures_names: {
    nodes: {{ signatures.names.nodes | tojson }},
    edges: {{ signatures.names.edges | tojson }},
    legend: {{ signatures.names.legend_items | tojson }}
  },
  signatures_categories: {
    nodes: {{ signatures.categories.nodes | tojson }},
    edges: {{ signatures.categories.edges | tojson }},
    legend: {{ signatures.categories.legend_items | tojson }}
  },
  dropped: {
    nodes: {{ dropped.nodes | tojson }},
    edges: {{ dropped.edges | tojson }},
    legend: {{ dropped.legend_items | tojson }}
  },
  api_names: {
    nodes: {{ api.names.nodes | tojson }},
    edges: {{ api.names.edges | tojson }},
    legend: {{ api.names.legend_items | tojson }}
  },
  api_categories: {
    nodes: {{ api.categories.nodes | tojson }},
    edges: {{ api.categories.edges | tojson }},
    legend: {{ api.categories.legend_items | tojson }}
  },
  {% for sec in behavior_summary.sections %}
  "behavior_summary_{{ sec }}": {
    nodes: {{ behavior_summary.data[sec].nodes | tojson }},
    edges: {{ behavior_summary.data[sec].edges | tojson }},
    legend: {{ behavior_summary.data[sec].legend_items | tojson }}
  }{% if not loop.last %},{% endif %}
  {% endfor %}
};

var behaviorSections = {{ behavior_summary.sections | tojson }};

/* DOM */
var container = document.getElementById("graph");
var legendEl = document.getElementById("legend");
var overlay = document.getElementById("loadingOverlay");
var bar = document.getElementById("loadingBar");
var cancelBtn = document.getElementById("cancelGraphBtn");

/* State */
var currentMain = "functions";
var currentMode = "names";                 // for signatures/api
var currentBehaviorSection = null;         // for behavior_summary
var generationCancelled = false;

/* vis-network options */
var options = {
  nodes: {
    shape: "dot",
    margin: { top: 10, right: 12, bottom: 10, left: 12 }, // padding around labels
    widthConstraint: { maximum: 320 },
    scaling: { min: 10, max: 60 },
    font: {
      color: "#ffffff",
      size: 14,
      face: "monospace"
    }
  },
  edges: { color: { color: "#6e7681" } },
  physics: { enabled: true, solver: "forceAtlas2Based" }
};

var network = new vis.Network(container, { nodes: [], edges: [] }, options);

/* Loading UI */
function showLoading() {
  generationCancelled = false;
  bar.style.width = "0%";
  overlay.style.display = "flex";
}
function hideLoading() {
  overlay.style.display = "none";
}
function setLegend(html) {
  legendEl.innerHTML = html || "";
}

/* Cancel */
function cancelGraphGeneration() {
  generationCancelled = true;
  try {
    network.stopSimulation();
    network.setOptions({ physics: false });
  } catch (e) {}
  hideLoading();
}
cancelBtn.addEventListener("click", cancelGraphGeneration);

/* Progress handlers */
network.on("stabilizationProgress", function (params) {
  if (generationCancelled) return;
  var pct = 0;
  if (params && params.total > 0) pct = Math.round((params.iterations / params.total) * 100);
  bar.style.width = pct + "%";
});
network.on("stabilizationIterationsDone", function () {
  if (generationCancelled) return;
  bar.style.width = "100%";
  setTimeout(hideLoading, 150);
});

/* Dataset routing */
function resolveDatasetKey(main, mode) {
  if (main === "signatures") return (mode === "categories") ? "signatures_categories" : "signatures_names";
  if (main === "api") return (mode === "categories") ? "api_categories" : "api_names";
  if (main === "behavior_summary") return "behavior_summary_" + currentBehaviorSection;
  return main;
}

function setDatasetDirect(nodes, edges, legendHtml) {
  showLoading();
  network.setOptions({ physics: { enabled: true, solver: "forceAtlas2Based" } });
  network.setData({ nodes: nodes, edges: edges });
  setLegend(legendHtml);
}

/* Sidebar state */
function clearActiveDatasetButtons() {
  document.querySelectorAll(".sideBtn").forEach(function(b){ b.classList.remove("active"); });
}
function setActiveDatasetButton(main) {
  clearActiveDatasetButtons();
  var id = {
    "strings": "btn_strings",
    "functions": "btn_functions",
    "signatures": "btn_signatures",
    "behavior_summary": "btn_behavior",
    "dropped": "btn_dropped",
    "api": "btn_api"
  }[main];
  var el = document.getElementById(id);
  if (el) el.classList.add("active");
}
function setToggleActive(mode) {
  document.querySelectorAll(".miniToggle").forEach(function(b){ b.classList.remove("active"); });
  if (mode === "names") document.getElementById("toggleNames").classList.add("active");
  if (mode === "categories") document.getElementById("toggleCategories").classList.add("active");
}
function updateSidebarSections() {
  var toggleRow = document.getElementById("toggleRow");
  var behaviorRow = document.getElementById("behaviorRow");

  toggleRow.style.display = (currentMain === "signatures" || currentMain === "api") ? "block" : "none";
  behaviorRow.style.display = (currentMain === "behavior_summary") ? "block" : "none";

  if (toggleRow.style.display !== "none") setToggleActive(currentMode);
}

/* Behavior filtering UI */
function buildBehaviorButtons() {
  var wrap = document.getElementById("behaviorButtons");
  wrap.innerHTML = "";

  function mkBtn(label, value) {
    var b = document.createElement("button");
    b.className = "miniBtn";
    b.textContent = label;
    b.addEventListener("click", function () {
      currentBehaviorSection = value;
      highlightBehaviorButtons();
      applyBehaviorFilter(value);
    });
    wrap.appendChild(b);
  }

  (behaviorSections || []).forEach(function (s) { mkBtn(s, s); });
  highlightBehaviorButtons();
}

function highlightBehaviorButtons() {
  var wrap = document.getElementById("behaviorButtons");
  var buttons = wrap.querySelectorAll("button");
  buttons.forEach(function (b) {
    b.classList.remove("active");
    if (b.textContent === currentBehaviorSection) b.classList.add("active");
  });
}

function applyBehaviorFilter(section) {
  var key = "behavior_summary_" + section;
  var data = datasets[key];
  if (!data) return;
  setDatasetDirect(data.nodes, data.edges, data.legend);
}

/* Main setDataset dispatcher */
function setDataset(main, mode) {
  currentMain = main;
  if (mode) currentMode = mode;

  setActiveDatasetButton(currentMain);
  updateSidebarSections();

  if (currentMain === "behavior_summary") {
    applyBehaviorFilter(currentBehaviorSection);
    return;
  }

  var key = resolveDatasetKey(currentMain, currentMode);
  var data = datasets[key];
  setDatasetDirect(data.nodes, data.edges, data.legend);
}

/* Sidebar button events */
document.querySelectorAll(".sideBtn").forEach(function(btn) {
  btn.addEventListener("click", function() {
    var main = btn.getAttribute("data-dataset");
    if (!main) return;
    setDataset(main);
  });
});

/* Toggles */
document.getElementById("toggleNames").addEventListener("click", function () {
  setDataset(currentMain, "names");
});
document.getElementById("toggleCategories").addEventListener("click", function () {
  setDataset(currentMain, "categories");
});

/* Init */
buildBehaviorButtons();
if (behaviorSections.length > 0) currentBehaviorSection = behaviorSections[0];
setDataset("strings");
</script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        # ---- Parameters ----
        malcat_dir = request.form.get("malcat_dir")
        output_dir = request.form.get("output_dir")
        capev2_base_url = request.form.get("capev2_base_url")
        capev2_api_token = request.form.get("capev2_api_token")
        lcs_threshold = int(request.form.get("lcs_threshold", 8))
        similarity_function = request.form.get("similarity_function")
        similarity_threshold = int(request.form.get("similarity_threshold", 25))
        fully_normalize = request.form.get("fully_normalize", False)
        fully_normalize = True if "True" == fully_normalize else False
        dynamic_analysis = request.form.get("dynamic_analysis", False)
        dynamic_analysis = True if "True" == dynamic_analysis else False

        # ---- File upload ----
        files = request.files.getlist("files")
        for f in files:
            if f.filename:
                safe_name = secure_filename(f.filename)
                f.save(os.path.join(UPLOAD_DIR, safe_name))

        flash("Files uploaded and parameters received.", "success")

        context = {}
        try:
            context = run_pipeline(
                malcat_dir=malcat_dir,
                input_dir=UPLOAD_DIR,
                output_dir=output_dir,
                lcs_threshold=lcs_threshold,
                similarity_function=similarity_function,
                similarity_threshold=similarity_threshold,
                fully_normalize=fully_normalize,
                capev2_base_url=capev2_base_url,
                capev2_api_token=capev2_api_token,
                dynamic_analysis=dynamic_analysis,
            )
            flash("Pipeline executed successfully!", "success")
        except Exception as e:
            flash(f"Error during execution: {e}", "danger")

        return render_template_string(HTML_TEMPLATE, **context)

    return render_template("index.html")
    

if __name__ == "__main__":
    app.run(debug=True)