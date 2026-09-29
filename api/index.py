"""Vercel serverless entry point: exposes the Flask app from app.py."""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: F401  (Vercel serves this `app`)
