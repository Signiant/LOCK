"""
command line application and sample code for accessing a secret version.
"""

import logging
import httplib2
import pprint
import time
import sys
import googleapiclient
from google.oauth2 import service_account
from google.cloud import secretmanager
from datetime import datetime
from googleapiclient.discovery import build
from oauth2client.service_account import ServiceAccountCredentials

logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.CRITICAL)

def set_secret_manager(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['client_cred']
    # Create the Secret Manager client.
    try:
        client = secretmanager.SecretManagerServiceClient.from_service_account_json(auth)
    except Exception as e:
        logging.error("Error: {0}".format(e))
        return
    
    from project import values
    if values.DryRun is True:
        logging.info('Dry run ')
    else:
        # Build the resource name of the parent secret.
        try: 
            parent_access = client.secret_path(key_args.get('project_id'), key_args.get('key_name'))
            payload_access = values.access_key[0].encode('UTF-8')
            response = client.add_secret_version(parent_access, {'data': payload_access})
            logging.debug("Response: {0}".format(response))
        except Exception as e:
            logging.error("     ***** Exception trying to update Google Access Key - Key may need to be updated manually. Exception: {0}".format(e))
            return
        try: 
            parent_secret = client.secret_path(key_args.get('project_id'), key_args.get('key_secret'))
            payload_secret = values.access_key[1].encode('UTF-8')
            response = client.add_secret_version(parent_secret, {'data': payload_secret})
            logging.debug("Response: {0}".format(response))
        except Exception as e:
            logging.error("     ***** Exception trying to update Google Secret Key - Key may need to be updated manually. Exception: {0}".format(e))
            return

        logging.info("      Access key and Secret key written to Secret Manager")
        pass


def wait_for_operation(compute, project, region, operation):
    logging.info("      Starting rolling update for {0}".format(project))
    while True:
        result = compute.regionOperations().get(
            project=project,
            region=region,
            operation=operation).execute()

        if result['status'] == 'DONE':
            logging.info('      Done')
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(5)

def rotate_instance_groups(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['client_cred']

    credentials = service_account.Credentials.from_service_account_file(auth)
    #authenticate with compute api
    try:
        compute = build('compute', 'v1', credentials=credentials)
    except Exception as e:
        logging.error("     ***** Exception trying to authenticate with google: {0}".format(e))
        return
    logging.debug("Authorized")
    regions = key_args.get('regions')
    for region in regions:
        if region == "stage":
            region = "us-east4"
            project = "fv1-stage-us-east4"
            instance_group = "flight-v1-stage-rigm"
            max_unavailable=1
        else:
            project = "fv1-prod-" + region
            instance_group = "flight-v1-prod-rigm"
            max_unavailable=2

        #retrieve instance template in use
        try:
            project_list = compute.regionInstanceGroupManagers().list(
                project=project,
                region=region).execute()
            instance_template = project_list['items'][0]['versions'][0]['instanceTemplate']
        except Exception as e:
            logging.error("     ***** Unable to retrieve current instance template: {0}".format(e))
            return 
        logging.debug("template: {0}".format(project_list['items'][0]['versions'][0]['instanceTemplate']))
        #set version to current datetime
        version = str(datetime.now())
        #create body for patch update
        body = {   
            "updatePolicy": {
                "minimalAction": "REPLACE",
                "type": "PROACTIVE",
                "maxSurge": {
                    "fixed": 0
                },
                "maxUnavailable": { 
                    "fixed": max_unavailable
                },
                "minReadySec": 300,
                "replacementMethod": "recreate"
            },
            "versions": [
                {
                "instanceTemplate": instance_template,
                "name": version
                }
            ]
        }
        #run rolling update to get new keys
        try:
            operation = compute.regionInstanceGroupManagers().patch(
                project=project,
                region=region,
                instanceGroupManager=instance_group,
                body=body).execute()
            wait_for_operation(compute, project, region, operation['name'])
        except Exception as e:
            logging.error("     ***** Unable to update instance group: {0}".format(e))
            return 