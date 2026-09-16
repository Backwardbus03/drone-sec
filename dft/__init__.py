"""
Drone Forensic Toolkit (DFT)
Indigenous, modular digital forensic framework for UAV investigation.
Compliant with ISO/IEC 27037:2012 and ISO/IEC 27042:2015.
"""

from pathlib import Path

# Automatically discover and load .env at package root if present
try:
    from dotenv import load_dotenv
    for search_dir in [Path.cwd(), Path(__file__).resolve().parent.parent]:
        env_candidate = search_dir / ".env"
        if env_candidate.exists():
            load_dotenv(dotenv_path=env_candidate)
            break
    else:
        load_dotenv()
except Exception:
    pass

__version__ = "1.0.0"
__author__ = "DFT Engineering Team"
