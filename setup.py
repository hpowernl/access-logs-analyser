"""Setup script for  Access Log Analyzer."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hypernode-logcli",
    version="1.0.0",
    author="Hypernode Team",
    author_email="support@hypernode.com",
    description="Hypernode Access Log Analyzer - Advanced Nginx JSON log analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hypernode/hypernode-logcli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Topic :: Internet :: Log Analysis",
    ],
    python_requires=">=3.8",
    install_requires=[
        "rich>=13.0.0",
        "textual>=0.45.0",
        "pandas>=1.5.0",
        "watchdog>=3.0.0",
        "user-agents>=2.2.0",
        "click>=8.1.0",
        "plotly>=5.17.0",
        "kaleido>=0.2.1",
    ],
    entry_points={
        "console_scripts": [
            "logcli=logcli.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
