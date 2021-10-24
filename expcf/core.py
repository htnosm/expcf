#!/usr/bin/env python
# -*- coding: utf-8 -*-

import boto3
import re
import csv
from operator import itemgetter
from boto3.session import Session
from . import cli

cf = boto3.client('cloudfront')


def get_certificates(profile=None) -> dict:
    session = Session(profile_name=profile, region_name="us-east-1")
    acm = session.client('acm')
    paginator = acm.get_paginator('list_certificates')
    return [page['CertificateSummaryList'] for page in paginator.paginate()][0]


def write_tsv(file, data_dict) -> None:
    with open(file, 'w', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data_dict[0].keys(), delimiter="\t", quotechar='"')
        writer.writeheader()
        writer.writerows(data_dict)


class CfInfo():
    def __init__(self, distribution, certificates) -> None:
        self.distribution = distribution
        # AlternateDomainNames
        if 'Aliases' in distribution and 'Items' in distribution['Aliases']:
            self.alternate_domain_names = ";".join(sorted(distribution['Aliases']['Items']))
        else:
            self.alternate_domain_names = "-"
        # WebACL
        self.web_acl_id = re.sub("^.*/", "", distribution['WebACLId'])
        self.web_acl_name = re.sub("^.*/webacl/(.*)/.*$", "\\1", distribution['WebACLId'])
        self.web_acl = f"{self.web_acl_name} ({self.web_acl_id})" if len(self.web_acl_id) > 0 else "-"
        # ViewerCertificate
        viewer_certificate = distribution['ViewerCertificate']
        self.certificate = "-"
        if 'Certificate' in viewer_certificate:
            certificate_arn = viewer_certificate['Certificate']
            certificate_id = re.sub("^.*/", "", certificate_arn)
            certificate_domain = [c['DomainName'] for c in certificates if c['CertificateArn'] == certificate_arn][0]
            self.certificate = f"{certificate_domain} ({certificate_id})" if len(certificate_id) > 0 else "-"
        self.minimum_protocol_version = viewer_certificate['MinimumProtocolVersion'] if 'MinimumProtocolVersion' in viewer_certificate else "-"
        self.ssl_support_method = viewer_certificate['SSLSupportMethod'] if 'SSLSupportMethod' in viewer_certificate else "-"
        # DistributionConfig
        self.distribution_config = cf.get_distribution_config(Id=self.distribution['Id'])['DistributionConfig']
        if not self.distribution_config['Logging']['Enabled']:
            self.distribution_config['Logging']['Bucket'] = '-'
            self.distribution_config['Logging']['Prefix'] = '-'
        if len(self.distribution_config['DefaultRootObject']) == 0:
            self.distribution_config['DefaultRootObject'] = '-'
        # GeoRestriction
        geo_restrictions = self.distribution_config['Restrictions']['GeoRestriction']
        self.geo_restriction = geo_restrictions['RestrictionType']
        if geo_restrictions['Quantity'] > 0:
            self.geo_restriction = ";".join(sorted(geo_restrictions['Items']))
        # additional CloudWatch metrics
        monitoring_subscription = cf.get_monitoring_subscription(DistributionId=self.distribution['Id'])['MonitoringSubscription']
        self.additional_metrics = monitoring_subscription['RealtimeMetricsSubscriptionConfig']['RealtimeMetricsSubscriptionStatus']

    def generate_distribution_info(self) -> dict:
        return {
            'DistributionId': self.distribution['Id'],
            'AlternateDomainNames': self.alternate_domain_names,
            'DomainName': self.distribution['DomainName'],
            'Description': self.distribution['Comment'],
            'PriceClass': self.distribution['PriceClass'],
            'HttpVersion': self.distribution['HttpVersion'],
            'WebACL': self.web_acl,
            'ViewerCertificate': self.certificate,
            'SecurityPolicy': self.minimum_protocol_version,
            'SSLSupportMethod': self.ssl_support_method,
            'Logging': self.distribution_config['Logging']['Enabled'],
            'Logging.Bucket': self.distribution_config['Logging']['Bucket'],
            'Logging.Prefix': self.distribution_config['Logging']['Prefix'],
            'Logging.IncludeCookies': self.distribution_config['Logging']['IncludeCookies'],
            'DefaultRootObject': self.distribution_config['DefaultRootObject'],
            'IsIPV6Enabled': self.distribution_config['IsIPV6Enabled'],
            'Status': self.distribution['Status'],
            'Enabled': self.distribution_config['Enabled'],
            'GeoRestriction': self.geo_restriction,
            'AdditionalMetrics': self.additional_metrics,
        }

    def generate_origin_infos(self, secret_custom_headers=[]) -> list:
        origin_infos = []
        for origin in self.distribution_config['Origins']['Items']:
            # OriginType
            if 'S3OriginConfig' in origin:
                origin_type = 'S3'
                oai = origin['S3OriginConfig']['OriginAccessIdentity'] if 'OriginAccessIdentity' in origin['S3OriginConfig'] else '-'
            elif 'CustomOriginConfig' in origin:
                origin_type = 'Custom'
                custom_origin_config = origin['CustomOriginConfig']
                custom_origin_params = {}
                for key in ["OriginProtocolPolicy", "HTTPPort", "HTTPSPort", "OriginReadTimeout", "OriginKeepaliveTimeout"]:
                    custom_origin_params[key] = custom_origin_config[key] if key in custom_origin_config else "-"
                if 'OriginSslProtocols' in custom_origin_config and custom_origin_config['OriginSslProtocols']['Quantity'] > 0:
                    origin_ssl_protocols = ";".join(sorted(custom_origin_config['OriginSslProtocols']['Items']))
                else:
                    origin_ssl_protocols = '-'
            else:
                origin_type = 'Unknown'

            # OriginShield
            if 'OriginShield' in origin and origin['OriginShield']['Enabled']:
                origin_shield = origin['OriginShield']['OriginShieldRegion']
            else:
                origin_shield = False

            # CustomHeaders
            if 'CustomHeaders' in origin and origin['CustomHeaders']['Quantity'] > 0:
                origin_custom_header_items = []
                for item in origin['CustomHeaders']['Items']:
                    if item['HeaderName'] in secret_custom_headers:
                        origin_custom_header_items.append(f"{item['HeaderName']}:*****")
                    else:
                        origin_custom_header_items.append(f"{item['HeaderName']}:{item['HeaderValue']}")
                origin_custom_headers = ";".join(sorted(origin_custom_header_items))
            else:
                origin_custom_headers = '-'

            origin_info = {
                'DistributionId': self.distribution['Id'],
                'AlternateDomainNames': self.alternate_domain_names,
                'OriginName': origin['Id'],
                'OriginDomain': origin['DomainName'],
                'OriginPath': origin['OriginPath'],
                'OriginType': origin_type,
                'OriginShield': origin_shield,
                'OriginAccessIdentity': oai if origin_type == 'S3' else '-',
                'OriginProtocolPolicy': custom_origin_params['OriginProtocolPolicy'] if origin_type == 'Custom' else '-',
                'HTTPPort': custom_origin_params['HTTPPort'] if origin_type == 'Custom' else '-',
                'HTTPSPort': custom_origin_params['HTTPSPort'] if origin_type == 'Custom' else '-',
                'OriginSslProtocols': origin_ssl_protocols if origin_type == 'Custom' else '-',
                'OriginReadTimeout': custom_origin_params['OriginReadTimeout'] if origin_type == 'Custom' else '-',
                'OriginKeepaliveTimeout': custom_origin_params['OriginKeepaliveTimeout'] if origin_type == 'Custom' else '-',
                'ConnectionAttempts': origin['ConnectionAttempts'],
                'ConnectionTimeout': origin['ConnectionTimeout'],
                'CustomHeaders': origin_custom_headers,
            }
            origin_infos.append(origin_info)
        return origin_infos

    def generate_behavior_infos(self) -> list:
        behavior_infos = []

        behaviors = []
        if self.distribution_config['CacheBehaviors']['Quantity'] > 0:
            behaviors = self.distribution_config['CacheBehaviors']['Items']
        behaviors.extend([self.distribution_config['DefaultCacheBehavior']])
        precedence = 0

        for behavior in behaviors:
            path_pattern = behavior['PathPattern'] if 'PathPattern' in behavior else "Default(*)"

            # CachePolicy
            cache_policy_params = {
                'Name': '-',
                'MinTTL': 0,
                'MaxTTL': 0,
                'DefaultTTL': 0,
                'Headers': 'none',
                'QueryStrings': 'none',
                'Cookies': 'none',
                'Gzip': False,
                'Brotli': False,
            }
            if 'CachePolicyId' in behavior and len(behavior['CachePolicyId']) > 0:
                cache_policy_config = cf.get_cache_policy(Id=behavior['CachePolicyId'])['CachePolicy']['CachePolicyConfig']
                cache_policy_params['Name'] = f"{cache_policy_config['Name']}({behavior['CachePolicyId']})"
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
                for key in ["MinTTL", "MaxTTL", "DefaultTTL"]:
                    cache_policy_params[key] = cache_policy_config[key] if key in cache_policy_config else cache_policy_params[key]
                for key in ["Gzip", "Brotli"]:
                    cache_policy_params[key] = params[f"EnableAcceptEncodin{key}"] if f"EnableAcceptEncodin{key}" in params else cache_policy_params[key]
            else:
                forwarded_values = behavior['ForwardedValues']
                if 'Headers' in behavior:
                    cache_policy_params['Headers'] = ";".join(sorted(behavior['Headers']['Items']))
                if 'QueryStrings' in forwarded_values:
                    query_strings = forwarded_values['QueryString']
                    if 'QueryStringCacheKeys' in query_strings and query_strings['QueryStringCacheKeys']['Quantity'] > 0:
                        query_strings = ";".join(sorted(query_strings['QueryStringCacheKeys']['Items']))
                    cache_policy_params['QueryStrings'] = query_strings
                if 'Cookies' in forwarded_values['Cookies']:
                    cookies = forwarded_values['Cookies']['Forward']
                    if forwarded_values['Cookies']['WhitelistedNames']['Quantity'] > 0:
                        cookies = ";".join(sorted(forwarded_values['Cookies']['WhitelistedNames']['Items']))
                    cache_policy_params['Cookies'] = cookies
                for key in ["MinTTL", "MaxTTL", "DefaultTTL"]:
                    cache_policy_params[key] = behavior[key] if key in behavior else cache_policy_params[key]
                cache_policy_params['Gzip'] = '-'
                cache_policy_params['Brotli'] = '-'

            # OriginRequestPolicy
            origin_request_policy_params = {
                'Name': '-',
                'HeaderBehavior': 'none',
                'QueryStringBehavior': 'none',
                'CookieBehavior': 'none',
            }
            if 'OriginRequestPolicyId' in behavior and len(behavior['OriginRequestPolicyId']) > 0:
                origin_request_policy_config = cf.get_origin_request_policy(Id=behavior['OriginRequestPolicyId'])['OriginRequestPolicy']['OriginRequestPolicyConfig']
                origin_request_policy_params['Name'] = f"{origin_request_policy_config['Name']}({behavior['OriginRequestPolicyId']})"
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
            if 'TrustedKeyGroups' in behavior and behavior['TrustedKeyGroups']['Quantity'] > 0:
                restrict_viewer_access = ";".join(sorted(behavior['TrustedKeyGroups']['Items']))
            elif 'TrustedSigners' in behavior and behavior['TrustedSigners']['Quantity'] > 0:
                restrict_viewer_access = ";".join(sorted(behavior['TrustedSigners']['Items']))
            else:
                restrict_viewer_access = False

            # FieldLevelEncryptionId
            field_level_encryption_id = behavior['FieldLevelEncryptionId'] if len(behavior['FieldLevelEncryptionId']) > 0 else '-'

            # FunctionAssociations
            function_associations = {
                'viewer-request': '-',
                'viewer-response': '-',
                'origin-request': '-',
                'origin-response': '-',
            }
            if 'LambdaFunctionAssociations' in behavior and behavior['LambdaFunctionAssociations']['Quantity'] > 0:
                for f in behavior['LambdaFunctionAssociations']['Items']:
                    lambda_function_name = re.sub("^.*:function:", "", f['LambdaFunctionARN'])
                    function_associations[f['EventType']] = f"Lambda@Edge;{lambda_function_name};IncludeBody={f['IncludeBody']}"
            if 'FunctionAssociations' in behavior and behavior['FunctionAssociations']['Quantity'] > 0:
                for f in behavior['FunctionAssociations']['Items']:
                    function_name = re.sub("^.*:function/", "", f['FunctionARN'])
                    function_associations[f['EventType']] = f"CloudFrontFunctions;{function_name}"

            behavior_info = {
                'DistributionId': self.distribution['Id'],
                'AlternateDomainNames': self.alternate_domain_names,
                'Precedence': precedence,
                'PathPattern': path_pattern,
                'TargetOriginId': behavior['TargetOriginId'],
                'ViewerProtocolPolicy': behavior['ViewerProtocolPolicy'],
                'Compress': behavior['Compress'],
                'AllowedMethods': ";".join(behavior['AllowedMethods']['Items']),
                'CachedMethods': ";".join(behavior['AllowedMethods']['CachedMethods']['Items']),
                'CachePolicy': cache_policy_params['Name'],
                'MinTTL': cache_policy_params['MinTTL'],
                'MaxTTL': cache_policy_params['MaxTTL'],
                'DefaultTTL': cache_policy_params['DefaultTTL'],
                'Headers': cache_policy_params['Headers'],
                'QueryStrings': cache_policy_params['QueryStrings'],
                'Cookies': cache_policy_params['Cookies'],
                'Gzip': cache_policy_params['Gzip'],
                'Brotli': cache_policy_params['Brotli'],
                'OriginRequestPolicy': origin_request_policy_params['Name'],
                'HeaderBehavior': origin_request_policy_params['HeaderBehavior'],
                'QueryStringBehavior': origin_request_policy_params['QueryStringBehavior'],
                'CookieBehavior': origin_request_policy_params['CookieBehavior'],
                'RestrictViewerAccess': restrict_viewer_access,
                'SmoothStreaming': behavior['SmoothStreaming'],
                'FieldLevelEncryptionId': field_level_encryption_id,
                'FunctionAssociation(ViewerRequest)': function_associations['viewer-request'],
                'FunctionAssociation(ViewerResponse)': function_associations['viewer-response'],
                'FunctionAssociation(OriginRequest)': function_associations['origin-request'],
                'FunctionAssociation(OriginResponse)': function_associations['origin-response'],
            }
            behavior_infos.append(behavior_info)
            precedence += 1
        return behavior_infos

    def generate_error_pages_infos(self) -> list:
        error_pages_infos = []
        custom_error_responses = self.distribution_config['CustomErrorResponses']
        items = custom_error_responses['Items'] if custom_error_responses['Quantity'] > 0 else []

        for i in [400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504]:
            error_pages_info = {
                'DistributionId': self.distribution['Id'],
                'AlternateDomainNames': self.alternate_domain_names,
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
        return error_pages_infos


def main():
    args = cli.arg_parse()
    if args.profile is not None:
        global cf
        session = Session(profile_name=args.profile)
        cf = session.client('cloudfront')
    secret_custom_headers = [] if args.exclude is None else args.exclude.split(',')

    paginator = cf.get_paginator('list_distributions')
    try:
        list_distributions = [page['DistributionList']['Items'] for page in paginator.paginate()][0]
    except Exception as e:
        raise e

    try:
        certificates = get_certificates(args.profile)
    except Exception as e:
        raise e

    distribution_infos = []
    origin_infos = []
    behavior_infos = []
    error_pages_infos = []
    for distribution in list_distributions:
        cf_info = CfInfo(distribution, certificates)

        distribution_infos.append(cf_info.generate_distribution_info())
        origin_infos.extend(cf_info.generate_origin_infos(secret_custom_headers))
        behavior_infos.extend(cf_info.generate_behavior_infos())
        error_pages_infos.extend(cf_info.generate_error_pages_infos())

    write_tsv('./distribution.tsv', sorted(distribution_infos, key=itemgetter('AlternateDomainNames')))
    write_tsv('./origins.tsv', sorted(origin_infos, key=itemgetter('AlternateDomainNames')))
    write_tsv('./behaviors.tsv', sorted(behavior_infos, key=itemgetter('AlternateDomainNames', 'Precedence')))
    write_tsv('./error_pages.tsv', sorted(error_pages_infos, key=itemgetter('AlternateDomainNames', 'ErrorCode')))


if __name__ == '__main__':
    main()
