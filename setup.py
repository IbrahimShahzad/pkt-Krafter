import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pkt-Krafter-IBRAHIMSHAHZAD",
    version="0.0.1",
    author="Ibrahim Shahzad"
    author_email="ibrahim.shahzad.mirza@gmail.com",
    description="a simple python library for creating packets",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/IbrahimShahzad/pkt-Krafter/tree/pyKraft",
    project_urls={
        "Bug Tracker": "https://github.com/IbrahimShahzad/pkt-Krafter/tree/pyKraftt/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
)