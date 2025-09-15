from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="advanced-antivirus",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Advanced Antivirus with YARA rules and heuristic analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/advanced-antivirus",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "colorama>=0.4.6",
        "yara-python>=4.2.3",
        "pefile>=2023.2.7",
        "python-magic>=0.4.27",
        "psutil>=5.9.5",
        "watchdog>=3.0.0",
        "pywin32>=306; sys_platform == 'win32'",
        "python-dotenv>=1.0.0",
        "pycryptodome>=3.18.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=1.22.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "antivirus=antivirus.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
)
