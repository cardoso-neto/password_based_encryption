from typing import List

import setuptools


def read_multiline_as_list(file_path: str) -> List[str]:
    with open(file_path) as fh:
        contents = fh.read().split("\n")
        if contents[-1] == "":
            contents.pop()
        return contents


with open("README.md", "r") as fh:
    long_description = fh.read()

requirements = read_multiline_as_list("requirements.txt")

# classifiers = read_multiline_as_list("classifiers.txt")

setuptools.setup(
    name="password_based_encryption",
    version="1.0.0",
    author="Nei Cardoso de Oliveira Neto",
    author_email="nei.neto@hotmail.com",
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cardoso-neto/password_based_encryption/",
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    # classifiers=classifiers,
    keywords='fernet, deterministic key derivation from password',
    entry_points = {
        'console_scripts': [
            # 'script-name=module:function',
        ],
    },
    python_requires=">=3.7, <3.10",
    install_requires=requirements,
)
