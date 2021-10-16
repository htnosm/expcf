# expcf
Export describe CloudFrontDistribution configuration to tsv

## Description

- Output in tsv format to the current directory
    - distribution.tsv
    - origins.tsv
    - behaviors.tsv
    - error_pages.tsv

## Installation

```
pip install git+https://github.com/htnosm/expcf.git
```

```
python setup.py develop
```

## Usage

```
expcf
```

### Specify the AWS profile

```
expcf -p your_aws_profile
```
