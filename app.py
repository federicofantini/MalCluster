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
<title>Cluster Graph</title>
<link rel="stylesheet" href="https://unpkg.com/vis-network/styles/vis-network.css" />
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>

<style>
  body {
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      background-color: #0d1117;
  }

  #graph { width: 100vw; height: 100vh; border: 1px solid #ccc; }

  #legend {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(255,255,255,0.9);
      border: 1px solid #ccc;
      padding: 10px;
      border-radius: 5px;
  }

  .legend-item { display: flex; align-items: center; margin-bottom: 5px; }
  .legend-color { width: 15px; height: 15px; margin-right: 5px; border-radius: 50%; }
</style>
</head>
<body>

<div id="graph"></div>

<div id="legend">
  {{ legend_items | safe }}
</div>

<script>
var nodes = new vis.DataSet({{ nodes | safe }});
var edges = new vis.DataSet({{ edges | safe }});

{% raw %}
var container = document.getElementById('graph');
var data = { nodes: nodes, edges: edges };

var options = {
    nodes: {
        shape: "dot",
        margin: 8,
        widthConstraint: { maximum: 300 }
    },
    physics: {
        enabled: true,
        solver: "forceAtlas2Based"
    }
};

var network = new vis.Network(container, data, options);
{% endraw %}
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
        lcs_threshold = int(request.form.get("lcs_threshold", 8))
        similarity_function = request.form.get("similarity_function")
        similarity_threshold = int(request.form.get("similarity_threshold", 25))
        fully_normalize = request.form.get("fully_normalize", False)

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
            )
            flash("Pipeline executed successfully!", "success")
        except Exception as e:
            flash(f"Error during execution: {e}", "danger")

        return render_template_string(HTML_TEMPLATE, **context)

    return render_template("index.html")
    

if __name__ == "__main__":
    app.run(debug=True)