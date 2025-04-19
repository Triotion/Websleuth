#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="websleuth",
    version="1.0.0",
    author="Triotion",
    author_email="",  # Add your email if you wish
    description="Advanced Website OSINT and Penetration Testing Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Triotion/websleuth",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "websleuth=websleuth.websleuth:main",
        ],
    },
) 