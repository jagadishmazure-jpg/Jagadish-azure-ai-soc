"""Agentic SOC on Azure, offline-first: synthetic Sentinel / Defender XDR-shaped data, a pure-Python KQL
engine, Microsoft Agent Framework agents and human-approved containment for a fictional MSSP."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config"
DETECTIONS = ROOT / "detections"
DATA = ROOT / "data"
RUNBOOKS = ROOT / "runbooks"
OUT = ROOT / "out"

__all__ = ["CONFIG", "DATA", "DETECTIONS", "OUT", "ROOT", "RUNBOOKS"]
