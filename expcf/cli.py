#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


def arg_parse():
    parser = argparse.ArgumentParser(description='Export describe CloudFrontDistribution configuration to tsv')

    parser.add_argument('-p', '--profile', help='AWS Profile')

    return parser.parse_args()
