#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


def arg_parse():
    parser = argparse.ArgumentParser(description='Export describe CloudFrontDistribution configuration to tsv')

    parser.add_argument('-p', '--profile', help='AWS Profile')
    parser.add_argument('-d', '--directory', help='tsv output directory. Default is current directory.')
    parser.add_argument('-x', '--exclude', help='Mask custom headers of sensitive value. Specifies the comma separated values.')

    return parser.parse_args()
