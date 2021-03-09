#!/bin/python

import json
import sys

project_name = sys.argv[1]
data = sys.stdin.readlines()

package_name = project_name.replace("-", "_")
metadata = json.loads(data[0])

for package in metadata["packages"]:
    if package["name"] == package_name:
        print(package["version"])
