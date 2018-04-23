"""
parameter_store.py

AWS Parameter Store help methods - currently extending boto3
"""

import logging
import sys
import os
from project import values
from project.plugins.iam import get_ssm_client


def _log_and_print_to_console(msg, log_level='info'):
    """
    Print a message to the console and log it to a file
    :param msg: the message to print and log
    :param log_level: the logging level for the mesage
    """
    log_func = {'info': logging.info, 'warn': logging.warn, 'error': logging.error}
    print(msg)
    log_func[log_level.lower()](msg)


def set_param_in_region(configMap,region, parameter, value, value_is_file=False, description=None, encrypt=False, key=None):
    if not region:
        _log_and_print_to_console("ERROR: You must supply a region", 'error')
        sys.exit(1)

    if not value:
        _log_and_print_to_console("ERROR: You must supply a value for the parameter", 'error')
        sys.exit(1)

    return_value = None

    ssm = get_ssm_client(configMap)

    if encrypt:
        type = "SecureString"
    else:
        type = 'String'

    if value_is_file and not os.path.exists(value):
        _log_and_print_to_console("ERROR: File Value provided, but file does not exist", 'error')
        sys.exit(1)
    if values.DryRun is True:
        logging.info('Dry run of put_parameter')
    else:
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


def set_paramameter(configMap,region_list, param_name, value, value_is_file=False, description=None, encrypt=False, key=None):
    result = {}
    for region in region_list:
        logging.debug("Checking region: " + region)
        result[region] = set_param_in_region(configMap,region, param_name, value, value_is_file, description, encrypt, key)
    return result


def set_param(configMap, username, **key_args):

    if key_args.get('encrypt') == 'True':
        encrypt = True
    else:
        encrypt = False

    value = key_args.get('value').replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1])

    result = set_paramameter(configMap,key_args.get('region_list'), key_args.get('param_name'), value, value_is_file=False, description=None, encrypt=encrypt, key=key_args.get('key'))
    for region in result:
        logging.critical(region + ': ' + ("Success" if result[region] == 200 else "Failed"))