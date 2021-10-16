from setuptools import setup, find_packages

with open('requirements.txt') as requirements_file:
    install_requirements = requirements_file.read().splitlines()

setup(
    name="expcf",
    version="0.0.1",
    description="Export describe CloudFrontDistribution",
    author="htnosm",
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
