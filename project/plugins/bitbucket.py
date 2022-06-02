import json
import logging

import boto3
import requests

from project import values

logging.getLogger('botocore').setLevel(logging.CRITICAL)


def __get_bitbucket_token(config_map,  **kwargs):
    # Retrieve the Bitbucket api key and api from parameter store, and get a Bitbucket api token
    if kwargs.get('credential_profile') is not None:
        profile_name = kwargs.get('credential_profile')
        session = boto3.Session(profile_name=profile_name, region_name='us-east-1')
    elif values.profile is not None:
        session = boto3.Session(region_name='us-east-1')
    else:
        session = boto3.Session(aws_access_key_id=config_map['Global']['id'],
                                aws_secret_access_key=config_map['Global']['secret'],
                                region_name='us-east-1')

    try:
        ssm_client = session.client('ssm')
        bb_api_key = ssm_client.get_parameter(Name='LOCK.bb_api_key', WithDecryption=True)['Parameter']['Value']
        bb_api_secret = ssm_client.get_parameter(Name='LOCK.bb_api_secret', WithDecryption=True)['Parameter']['Value']
    except Exception as e:
        logging.error(f'Error retrieving Bitbucket credentials from Parameter Store: {e}')
        return None

    token_url = 'https://bitbucket.org/site/oauth2/access_token'
    data = {'grant_type': 'client_credentials', 'client_id': bb_api_key, 'client_secret': bb_api_secret}
    access_token = requests.post(token_url, data=data).json()
    api_token = access_token['access_token']
    return api_token


def __get_variable(api_token, workspace, variable_uuid):
    headers = dict()
    headers['Accept'] = 'application/json'
    headers['Authorization'] = f'Bearer {api_token}'
    headers['Content-Type'] = 'application/json'

    url = f'https://api.bitbucket.org/2.0/workspaces/{workspace}/pipelines-config/variables/{variable_uuid}'
    response = requests.get(url, headers=headers)
    details = json.loads(response.text)
    return details


def __put_variable(api_token, workspace, variable_uuid, variable_details):
    headers = dict()
    headers['Accept'] = 'application/json'
    headers['Authorization'] = f'Bearer {api_token}'
    headers['Content-Type'] = 'application/json'

    url = f'https://api.bitbucket.org/2.0/workspaces/{workspace}/pipelines-config/variables/{variable_uuid}'
    payload = json.dumps(variable_details)
    response = requests.put(url, data=payload, headers=headers)
    if response.status_code != 200:
        logging.error(f'Error updating Bitbucket variable {response.status_code}: {response.text}')
    return None


def __update_variable(api_token, workspace, variable_uuid, variable_value):
    variable_details = __get_variable(api_token, workspace, variable_uuid)
    variable_details['value'] = variable_value
    __put_variable(api_token, workspace, variable_uuid, variable_details)
    return None


def update_variables(config_map, username, **kwargs):
    aws_access_key_id = values.access_key[0]
    aws_secret_access_key = values.access_key[1]

    api_token = __get_bitbucket_token(config_map, **kwargs)
    if not api_token:
        logging.error(f'Missing Bitbucket API token. Unable to update variables for {username}: aborting')
        return None
    workspace = kwargs.get('workspace')
    access_key_uuid = kwargs.get('access_key_uuid')
    secret_access_key_uuid = kwargs.get('secret_key_uuid')

    logging.info(f'Updating access key variable for {username}')
    __update_variable(api_token, workspace, access_key_uuid, aws_access_key_id)

    logging.info(f'Updating secret access key variable for {username}')
    __update_variable(api_token, workspace, secret_access_key_uuid, aws_secret_access_key)

    return None
