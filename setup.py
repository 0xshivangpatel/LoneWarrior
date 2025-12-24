#!/usr/bin/env python3
"""
LoneWarrior - Autonomous Security Agent
Setup configuration
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

# Add requests if not in requirements
if "requests" not in [r.split("==")[0].split(">=")[0] for r in requirements]:
    requirements.append("requests>=2.25.0")

setup(
    name="lonewarrior",
    version="1.0.0",
    author="LoneWarrior Contributors",
    author_email="",
    description="Autonomous security agent that learns, detects, and acts independently",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/lonewarrior",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "lonewarrior=lonewarrior.__main__:main",
            "lw=lonewarrior.cli.main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "lonewarrior": [
            "config/*.yaml",
            "threat_intel/*.txt",
            "web/static/*",
            "web/templates/*",
        ],
    },
    zip_safe=False,
)
