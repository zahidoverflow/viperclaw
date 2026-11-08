"""Sample vulnerable route handler for demonstrating ViperClaw multi-language taint analysis."""

import os
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/api/v1/network/ping")
def diagnostic_ping():
    target = request.args.get("target", "127.0.0.1")
    # Deliberate source-to-sink taint flow for static analyzer demonstration
    output = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return output
