from setuptools import setup, find_packages

with open("README.md", "r") as readme_file:
    readme = readme_file.read()

requirements = []

setup(
    name="certicat",
    version="0.0.1",
    author="Dror Moyal",
    author_email="moyaldror@gmail.com",
    description="A bundle of a library and a tool to clone X.509 certificates",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/certbuilder/certicat",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3.7.2",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
)
