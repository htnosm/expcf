from setuptools import setup, find_packages

with open('requirements.txt') as requirements_file:
    install_requirements = requirements_file.read().splitlines()

with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="expcf",
    version="0.0.1",
    description="Export describe CloudFrontDistribution",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/htnosm/expcf",
    author="htnosm",
    author_email='htnosm@gmail.com',
    license='MIT',
    packages=find_packages(),
    install_requires=install_requirements,
    entry_points={
        "console_scripts": [
            "expcf=expcf.core:main",
        ]
    },
    classifiers=[
        'Programming Language :: Python :: 3.9',
    ]
)
