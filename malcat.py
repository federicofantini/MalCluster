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

import importlib.util
from types import ModuleType
from pathlib import Path

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