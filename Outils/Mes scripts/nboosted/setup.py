from setuptools import find_packages, setup

setup(
    name="nboosted",
    version="0.1.0",
    description="CloakQuest3r + Nmap workflow: trouve les IP reelles derriere Cloudflare puis les scanne avec nmap -sV -sC",
    packages=find_packages(include=["nboosted", "nboosted.*"]),
    install_requires=[
        "requests",
        "colorama",
        "beautifulsoup4",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "nboosted=nboosted.cli:main",
        ],
    },
    python_requires=">=3.8",
)
