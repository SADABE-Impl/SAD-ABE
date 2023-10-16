import setuptools

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setuptools.setup(
    name="ABE",
    version="0.1.0",
    description="Attribute-based Encryption",
    url="https://github.com/SADABE-Impl/SAD-ABE",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=2.7',
    include_package_data=True,
)
