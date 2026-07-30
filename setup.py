# Compatibility shim so `pip install -e .` works on older pip/setuptools that
# lack PEP 660 editable support. All configuration lives in pyproject.toml.
from setuptools import setup

setup()
