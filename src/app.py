#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto3
import re
import csv
from operator import itemgetter
from boto3.session import Session
#from pprint import pprint

cf = boto3.client('cloudfront')
secret_custome_headers = ['x-pre-shared-key']


def get_certificates():
    session = Session(region_name="us-east-1")
    acm = session.client('acm')
    paginator = acm.get_paginator('list_certificates')

    result = []
    for page in paginator.paginate():
        result.extend(page['CertificateSummaryList'])

    return result


def get_distribution_config(distribution_id):
    response = cf.get_distribution_config(
        Id=distribution_id
    )

    return response['DistributionConfig']


def write_tsv(file, data_dict):
    with open(file, 'w', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data_dict[0].keys(), delimiter="\t", quotechar='"')
        writer.writeheader()
        writer.writerows(data_dict)


def main():
    paginator = cf.get_paginator('list_distributions')

    try:
        list_distributions = [page['DistributionList']['Items'] for page in paginator.paginate()][0]
    except Exception as e:
        raise e

    try:
        certificates = get_certificates()
    except Exception as e:
        raise e

    distribution_infos = []
    origin_infos = []
    behavior_infos = []
    error_pages_infos = []
    for distribution in list_distributions:
        #pprint(distribution)
        distribution_info = {}
        origin_info = {}

        # AlternateDomainNames
        alternate_domain_names = ";".join(sorted(distribution['Aliases']['Items']))

        # WebACL
        web_acl_id = re.sub("^.*/", "", distribution['WebACLId'])
        web_acl_name = re.sub("^.*/webacl/(.*)/.*$", "\\1", distribution['WebACLId'])
        web_acl = f"{web_acl_name} ({web_acl_id})" if len(web_acl_id) > 0 else ""
        # ViewerCertificate
        certificate = ""
        minimum_protocol_version = ""
        if 'ViewerCertificate' in distribution:
            certificate_arn = distribution['ViewerCertificate']['Certificate']
            certificate_id = re.sub("^.*/", "", certificate_arn)
            certificate_domain = [ c['DomainName'] for c in certificates if c['CertificateArn'] == certificate_arn ][0]
            certificate = f"{certificate_domain} ({certificate_id})" if len(certificate_id) > 0 else ""
            minimum_protocol_version = distribution['ViewerCertificate']['MinimumProtocolVersion']
            ssl_support_method = distribution['ViewerCertificate']['SSLSupportMethod']

        # DistributionConfig
        distribution_config = get_distribution_config(distribution['Id'])
        #pprint(distribution_config)

        # GeoRestriction
        geo_restrictions = distribution_config['Restrictions']['GeoRestriction']
        geo_restriction = geo_restrictions['RestrictionType']
        if geo_restrictions['Quantity'] > 0:
                geo_restriction = ";".join(sorted(geo_restrictions['Items']))

        distribution_info = {
            'DistributionId': distribution['Id'],
            'AlternateDomainNames': alternate_domain_names,
            'DomainName': distribution['DomainName'],
            'Description': distribution['Comment'],
            'PriceClass': distribution['PriceClass'],
            'HttpVersion': distribution['HttpVersion'],
            'WebACL': web_acl,
            'ViewerCertificate': certificate,
            'SecurityPolicy': minimum_protocol_version,
            'SSLSupportMethod': ssl_support_method,
            'Logging': distribution_config['Logging']['Enabled'],
            'Logging.Bucket': distribution_config['Logging']['Bucket'],
            'Logging.Prefix': distribution_config['Logging']['Prefix'],
            'Logging.IncludeCookies': distribution_config['Logging']['IncludeCookies'],
            'DefaultRootObject': distribution_config['DefaultRootObject'],
            'IsIPV6Enabled': distribution_config['IsIPV6Enabled'],
            'Status': distribution['Status'],
            'Enabled': distribution_config['Enabled'],
            'GeoRestriction': geo_restriction,
        }
        distribution_infos.append(distribution_info)

        # Origins
        for origin in distribution_config['Origins']['Items']:
            oai = '-'
            origin_protocol_policy = '-'
            origin_http_port = '-'
            origin_https_port = '-'
            origin_ssl_protocols = '-'
            origin_read_timeout = '-'
            origin_keepalive_timeout = '-'
            origin_custom_headers = '-'

            if 'S3OriginConfig' in origin:
                origin_type = 'S3'
                if 'OriginAccessIdentity' in origin['S3OriginConfig']:
                    oai = origin['S3OriginConfig']['OriginAccessIdentity']
            elif 'CustomOriginConfig' in origin:
                custom_origin_config = origin['CustomOriginConfig']
                origin_type = 'Custom'
                origin_protocol_policy = custom_origin_config['OriginProtocolPolicy']
                origin_http_port = custom_origin_config['HTTPPort']
                origin_https_port = custom_origin_config['HTTPSPort']
                if custom_origin_config['OriginSslProtocols']['Quantity'] > 0:
                    origin_ssl_protocols = ";".join(sorted(custom_origin_config['OriginSslProtocols']['Items']))
                origin_read_timeout = custom_origin_config['OriginReadTimeout']
                origin_keepalive_timeout = custom_origin_config['OriginKeepaliveTimeout']
            else:
                origin_type = ''

            if origin['OriginShield']['Enabled']:
                origin_shield = origin['OriginShield']['OriginShieldRegion']
            else:
                origin_shield = False

            if origin['CustomHeaders']['Quantity'] > 0:
                origin_custom_header_items = []
                for item in origin['CustomHeaders']['Items']:
                    if item['HeaderName'] in secret_custome_headers:
                        origin_custom_header_items.append(f"{item['HeaderName']}:*****")
                    else:
                        origin_custom_header_items.append(f"{item['HeaderName']}:{item['HeaderValue']}")
                origin_custom_headers = ";".join(sorted(origin_custom_header_items))

            origin_info = {
                'DistributionId': distribution['Id'],
                'AlternateDomainNames': alternate_domain_names,
                'OriginName': origin['Id'],
                'OriginDomain': origin['DomainName'],
                'OriginPath': origin['OriginPath'],
                'OriginType': origin_type,
                'OriginShield': origin_shield,
                'OriginAccessIdentity': oai,
                'OriginProtocolPolicy': origin_protocol_policy,
                'HTTPPort': origin_http_port,
                'HTTPSPort': origin_https_port,
                'OriginSslProtocols': origin_ssl_protocols,
                'OriginReadTimeout': origin_read_timeout,
                'OriginKeepaliveTimeout': origin_keepalive_timeout,
                'ConnectionAttempts': origin['ConnectionAttempts'],
                'ConnectionTimeout': origin['ConnectionTimeout'],
                'CustomHeaders': origin_custom_headers,
            }
            origin_infos.append(origin_info)

        # Behavior
        behaviors = []
        if distribution_config['CacheBehaviors']['Quantity'] > 0:
            behaviors = distribution_config['CacheBehaviors']['Items']
        behaviors.extend([distribution_config['DefaultCacheBehavior']])
        precedence = 0
        for behavior in behaviors:
            path_pattern = behavior['PathPattern'] if 'PathPattern' in behavior else "Default(*)"

            # CachePolicy
            cache_policy_name = '-'
            cache_policy_params = {
                'Headers': 'none',
                'QueryStrings': 'none',
                'Cookies': 'none',
                'Gzip': False,
                'Brotli': False,
            }
            if len(behavior['CachePolicyId']) > 0:
                cache_policy_config = cf.get_cache_policy(Id=behavior['CachePolicyId'])['CachePolicy']['CachePolicyConfig']
                #pprint(cache_policy_config)
                cache_policy_name = f"{cache_policy_config['Name']}({behavior['CachePolicyId']})"
                params = cache_policy_config['ParametersInCacheKeyAndForwardedToOrigin']

                if 'Headers' in params['HeadersConfig']:
                    headers = params['HeadersConfig']['Headers']
                    cache_policy_params['Headers'] = ";".join(sorted(headers['Items']))
                if 'QueryStrings' in params['QueryStringsConfig']:
                    query_strings = params['QueryStringsConfig']['QueryStrings']
                    cache_policy_params['QueryStrings'] = ";".join(sorted(query_strings['Items']))
                if 'Cookies' in params['CookiesConfig']:
                    cookies = params['CookiesConfig']['Cookies']
                    cache_policy_params['Cookies'] = ";".join(sorted(cookies['Items']))

                cache_policy = {
                    'MinTTL': cache_policy_config['MinTTL'],
                    'MaxTTL': cache_policy_config['MaxTTL'],
                    'DefaultTTL': cache_policy_config['DefaultTTL'],
                    'Headers': cache_policy_params['Headers'],
                    'QueryStrings': cache_policy_params['QueryStrings'],
                    'Cookies': cache_policy_params['Cookies'],
                    'Gzip': cache_policy_params['Gzip'],
                    'Brotli': cache_policy_params['Brotli'],
                }
            else:
                forwarded_values = behavior['ForwardedValues']
                headers = ";".join(sorted(behavior['Headers']['Items']))
                query_strings = forwarded_values['QueryString']
                if forwarded_values['QueryString']['QueryStringCacheKeys']['Quantity'] > 0:
                    query_strings = ";".join(sorted(forwarded_values['QueryStringCacheKeys']['Items']))
                cookies = forwarded_values['Cookies']['Forward']
                if forwarded_values['Cookies']['WhitelistedNames']['Quantity'] > 0:
                    cookies = ";".join(sorted(forwarded_values['Cookies']['WhitelistedNames']['Items']))

                cache_policy = {
                    'MinTTL': behavior['MinTTL'],
                    'MaxTTL': behavior['MaxTTL'],
                    'DefaultTTL': behavior['DefaultTTL'],
                    'Headers': headers,
                    'QueryStrings': query_strings,
                    'Cookies': cookies,
                    'Gzip': cache_policy_params['Gzip'],
                    'Brotli': cache_policy_params['Brotli'],
                }

            # OriginRequestPolicy
            origin_request_policy_name = '-'
            origin_request_policy_params = {
                'HeaderBehavior': 'none',
                'QueryStringBehavior': 'none',
                'CookieBehavior': 'none',
            }
            if len(behavior['OriginRequestPolicyId']) > 0:
                origin_request_policy_config = cf.get_origin_request_policy(Id=behavior['OriginRequestPolicyId'])['OriginRequestPolicy']['OriginRequestPolicyConfig']
                #pprint(origin_request_policy_config)
                origin_request_policy_name = f"{origin_request_policy_config['Name']}({behavior['OriginRequestPolicyId']})"

                if 'Headers' in origin_request_policy_config['HeadersConfig']:
                    headers = origin_request_policy_config['HeadersConfig']['Headers']
                    origin_request_policy_params['HeaderBehavior'] = ";".join(sorted(headers['Items']))
                if 'QueryStrings' in origin_request_policy_config['QueryStringsConfig']:
                    query_strings = origin_request_policy_config['QueryStringsConfig']['QueryStrings']
                    origin_request_policy_params['QueryStringBehavior'] = ";".join(sorted(query_strings['Items']))
                if 'Cookies' in origin_request_policy_config['CookiesConfig']:
                    cookies = origin_request_policy_config['CookiesConfig']['Cookies']
                    origin_request_policy_params['CookieBehavior'] = ";".join(sorted(cookies['Items']))

            # RestrictViewerAccess
            if behavior['TrustedKeyGroups']['Quantity'] > 0:
                restrict_viewer_access = ";".join(sorted(behavior['TrustedKeyGroups']['Items']))
            elif behavior['TrustedSigners']['Quantity'] > 0:
                restrict_viewer_access = ";".join(sorted(behavior['TrustedSigners']['Items']))
            else:
                restrict_viewer_access = False

            # FieldLevelEncryptionId
            field_level_encryption_id = behavior['FieldLevelEncryptionId'] if len(behavior['FieldLevelEncryptionId']) > 0 else '-'

            # LambdaFunctionAssociations
            # TODO Functions
            lambda_function_associations = behavior['LambdaFunctionAssociations']['Quantity']

            behavior_info = {
                'DistributionId': distribution['Id'],
                'AlternateDomainNames': alternate_domain_names,
                'Precedence': precedence,
                'PathPattern': path_pattern,
                'TargetOriginId': behavior['TargetOriginId'],
                'ViewerProtocolPolicy': behavior['ViewerProtocolPolicy'],
                'Compress': behavior['Compress'],
                'AllowedMethods': ";".join(behavior['AllowedMethods']['Items']),
                'CachedMethods': ";".join(behavior['AllowedMethods']['CachedMethods']['Items']),
                'CachePolicy': cache_policy_name,
                'MinTTL': cache_policy['MinTTL'],
                'MaxTTL': cache_policy['MaxTTL'],
                'DefaultTTL': cache_policy['DefaultTTL'],
                'Headers': cache_policy['Headers'],
                'QueryStrings': cache_policy['QueryStrings'],
                'Cookies': cache_policy['Cookies'],
                'Gzip': cache_policy['Gzip'],
                'Brotli': cache_policy['Brotli'],
                'OriginRequestPolicy': origin_request_policy_name,
                'HeaderBehavior': origin_request_policy_params['HeaderBehavior'],
                'QueryStringBehavior': origin_request_policy_params['QueryStringBehavior'],
                'CookieBehavior': origin_request_policy_params['CookieBehavior'],
                'RestrictViewerAccess': restrict_viewer_access,
                'SmoothStreaming': behavior['SmoothStreaming'],
                'FieldLevelEncryptionId': field_level_encryption_id,
                'LambdaFunctionAssociations': lambda_function_associations,
            }
            behavior_infos.append(behavior_info)
            precedence += 1

        # ErrorPages(CustomErrorResponses)
        if distribution_config['CustomErrorResponses']['Quantity'] > 0:
            items = distribution_config['CustomErrorResponses']['Items']
        else:
            items = []
        for i in [400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504]:
            error_pages_info = {
                'DistributionId': distribution['Id'],
                'AlternateDomainNames': alternate_domain_names,
                'ErrorCode': i,
                'ErrorCachingMinTTL': 300,
                'ResponsePagePath': "-",
                'ResponseCode': "-"
            }
            for item in items:
                if i == item['ErrorCode']:
                    error_pages_info['ErrorCachingMinTTL'] = item['ErrorCachingMinTTL']
                    error_pages_info['ResponsePagePath'] = item['ResponsePagePath']
                    error_pages_info['ResponseCode'] = item['ResponseCode']
                    break
            error_pages_infos.append(error_pages_info)

    #pprint(distribution_infos)
    write_tsv('./distribution.tsv', sorted(distribution_infos, key=itemgetter('AlternateDomainNames')))
    #pprint(origin_infos)
    write_tsv('./origins.tsv', sorted(origin_infos, key=itemgetter('AlternateDomainNames')))
    #pprint(behavior_infos)
    write_tsv('./behaviors.tsv', sorted(behavior_infos, key=itemgetter('AlternateDomainNames', 'Precedence')))
    #pprint(error_pages_infos)
    write_tsv('./error_pages.tsv', sorted(error_pages_infos, key=itemgetter('AlternateDomainNames', 'ErrorCode')))


if __name__ == '__main__':
    main()
