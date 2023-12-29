from setuptools import setup, find_packages

__version__ = "1.5.1"

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
    package_data={
        'crypto_pkg': ['attacks/power_analysis/test_file.pickle'],
    },
    install_requires=requirements,
    author="programmingAthlete",
    author_email="luca.bonamino@hotmail.com",
    zip_safe=True,
    console_scripts={
        "crypto": "crypto.entry_point:main"
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
