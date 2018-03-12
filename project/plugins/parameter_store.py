"""
parameter_store.py

AWS Parameter Store help methods - currently extending boto3


Note:
    Credentials are required to communicate with AWS.
    aws cli profile can be passed in using --profile, or
    the following ENVIRONMENT VARIABLES can be set before
    running this script:
        AWS_ACCESS_KEY_ID
        AWS_SECRET_ACCESS_KEY
"""

import logging
import argparse
import sys
import os
import boto3, botocore


def _log_and_print_to_console(msg, log_level='info'):
    """
    Print a message to the console and log it to a file
    :param msg: the message to print and log
    :param log_level: the logging level for the mesage
    """
    log_func = {'info': logging.info, 'warn': logging.warn, 'error': logging.error}
    print(msg)
    log_func[log_level.lower()](msg)


def parse_file_into_string(file_path):
    with open(file_path) as f:
        return ''.join(f.readlines()).rstrip()


def parameter_exists(requested_param, region, profile=None):
    if get_param_from_region(requested_param, region, decrypt=False, profile=profile):
        return True
    else:
        return False


def get_param_from_region(requested_param, region, decrypt=False, profile=None):
    if not region:
        _log_and_print_to_console("ERROR: You must supply a region", 'error')
        sys.exit(1)

    return_value = None

    session = boto3.session.Session(profile_name=profile, region_name=region)
    ssm = session.client('ssm')

    result = ssm.get_parameters(Names=[requested_param], WithDecryption=decrypt)

    if result:
        if 'ResponseMetadata' in result:
            if 'HTTPStatusCode' in result['ResponseMetadata']:
                if result['ResponseMetadata']['HTTPStatusCode'] == 200:
                    if 'Parameters' in result:
                        for param in result['Parameters']:
                            if param['Name'] == requested_param:
                                return_value = param['Value']
                                break
    return return_value


def get_parameter(requested_param, region_list, decrypt=False, profile=None):
    result = {}

    for region in region_list:
        logging.debug("Checking region: " + region)
        result[region] = get_param_from_region(requested_param, region, decrypt, profile)
    return result


def set_param_in_region(region, parameter, value, value_is_file=False, description=None, encrypt=False, key=None, profile=None):
    if not region:
        _log_and_print_to_console("ERROR: You must supply a region", 'error')
        sys.exit(1)

    if not value:
        _log_and_print_to_console("ERROR: You must supply a value for the parameter", 'error')
        sys.exit(1)

    return_value = None

    session = boto3.session.Session(profile_name=profile, region_name=region)
    ssm = session.client('ssm')

    if encrypt:
        type = "SecureString"
    else:
        type = 'String'

    if value_is_file and not os.path.exists(value):
        _log_and_print_to_console("ERROR: File Value provided, but file does not exist", 'error')
        sys.exit(1)

    if value_is_file:
        value = parse_file_into_string(value)

    if description:
        if key:
            result = ssm.put_parameter(Name=parameter,
                                       Description=description,
                                       Value=value,
                                       Type=type,
                                       KeyId=key,
                                       Overwrite=True)
        else:
            result = ssm.put_parameter(Name=parameter,
                                       Description=description,
                                       Value=value,
                                       Type=type,
                                       Overwrite=True)
    else:
        if key:
            result = ssm.put_parameter(Name=parameter,
                                       Value=value,
                                       Type=type,
                                       KeyId=key,
                                       Overwrite=True)
        else:
            result = ssm.put_parameter(Name=parameter,
                                       Value=value,
                                       Type=type,
                                       Overwrite=True)

    if result:
        if 'ResponseMetadata' in result:
            if 'HTTPStatusCode' in result['ResponseMetadata']:
                return_value = result['ResponseMetadata']['HTTPStatusCode']
    return return_value


def set_paramameter(region_list, param_name, value, value_is_file=False, description=None, encrypt=False, key=None, profile=None):
    result = {}

    for region in region_list:
        logging.debug("Checking region: " + region)
        result[region] = set_param_in_region(region, param_name, value, value_is_file, description, encrypt, key, profile)
    return result


def delete_param_in_region(region, param_name, profile=None):
    if not region:
        _log_and_print_to_console("ERROR: You must supply a region", 'error')
        sys.exit(1)

    if not param_name:
        _log_and_print_to_console("ERROR: You must supply a parameter to delete", 'error')
        sys.exit(1)

    return_value = None

    session = boto3.session.Session(profile_name=profile, region_name=region)
    ssm = session.client('ssm')

    try:
        result = ssm.delete_parameter(Name=param_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            return 404
        else:
            _log_and_print_to_console('Unexpected error: %s' % e)
            return 404

    if result:
        if 'ResponseMetadata' in result:
            if 'HTTPStatusCode' in result['ResponseMetadata']:
                return_value = result['ResponseMetadata']['HTTPStatusCode']
    return return_value


def delete_paramameter(region_list, param_name, profile=None):
    result = {}

    for region in region_list:
        logging.debug("Checking region: " + region)
        result[region] = delete_param_in_region(region, param_name, profile)
    return result



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='parameter_store.py')

    me_cmd_group = parser.add_mutually_exclusive_group(required=True)
    me_cmd_group.add_argument("--get", help="Perform a Get", action="store_true")
    me_cmd_group.add_argument("--set", help="Perform a Set", action="store_true")
    me_cmd_group.add_argument("--delete", help="Perform a Delete", action="store_true")

    parser.add_argument("--param", help="Parameter name", dest='param', required=True)

    me_encrypt_group = parser.add_mutually_exclusive_group()
    me_encrypt_group.add_argument("--decrypt", help="Specify if parameter should be decrypted (for a GET)", action='store_true', default=False)
    me_encrypt_group.add_argument("--encrypt", help="Specify if parameter should be encrypted (for a SET)", action='store_true', default=False)

    me_value_group = parser.add_mutually_exclusive_group()
    me_value_group.add_argument("--value", help="Value of the parameter to set", dest='value')
    me_value_group.add_argument("--file-value", help="Use the contents of the given file for the value (multi-line not supported)", dest='file_value')

    parser.add_argument("--description", help="Description of the parameter to set", dest='description')
    parser.add_argument("--key", help="Parameter KeyID to use during set", dest='key')
    parser.add_argument("--regions", help="AWS Region(s) involved (space separated)", dest='regions', nargs='+', required=True)
    parser.add_argument("--profile",
                        help="The name of an aws cli profile to use.", dest='profile', required=False)
    parser.add_argument("--verbose", help="Turn on DEBUG logging", action='store_true', required=False)
    parser.add_argument("--dryrun", help="Do a dryrun - no changes will be performed", dest='dryrun',
                        action='store_true', default=False,
                        required=False)

    args = parser.parse_args()

    log_level = logging.INFO

    if args.verbose:
        print("Verbose logging selected")
        log_level = logging.DEBUG

    logging.basicConfig(filename='parameter_store.log', format='%(asctime)s - %(levelname)7s : %(message)s',
                        level=log_level)

    logging.info("INIT")

    if args.get:
        result = get_parameter(args.param, args.regions, args.decrypt, args.profile)
        for region in result:
            print(region + ': ' + (result[region] if result[region] else "Not Present"))

    if args.set:
        if not args.value and not args.file_value:
            _log_and_print_to_console("Must supply VALUE", "error")
            sys.exit(1)
        value_is_file = True if args.file_value else False
        param_value = args.file_value if args.file_value else args.value
        result = set_paramameter(args.regions, args.param, param_value, value_is_file, args.description, args.encrypt, args.key, args.profile)
        for region in result:
            print(region + ': ' + ("Success" if result[region] == 200 else "Failed"))

    if args.delete:
        result = delete_paramameter(args.regions, args.param, args.profile)
        for region in result:
            print(region + ': ' + ("Success" if result[region] == 200 else ("Not Found" if result[region] == 404 else "Failed")))