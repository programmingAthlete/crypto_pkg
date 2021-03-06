from setuptools import setup, find_packages

__version__ = "0.0.1"

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = f.read()

setup(
    name="crypto_pkg",
    description="A cryptoanalysis package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/programmingAthlete/crypto_pkg.git",
    version=__version__,
    package_dir={"": "src"},
    packages=find_packages(where="src", exclude=["*tests*"]),
    install_requires=requirements,
    author="programmingAthlete",
    zip_safe=True
)
