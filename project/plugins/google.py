"""
command line application and sample code for accessing a secret version.
"""

import logging
import os
import time
import tempfile
from datetime import datetime

from google.cloud import kms_v1, secretmanager, storage
from google.oauth2 import service_account
from googleapiclient.discovery import build

from project import values

logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.CRITICAL)


def set_secret_manager(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['client_cred']
    # Create the Secret Manager client.
    try:
        client = secretmanager.SecretManagerServiceClient.from_service_account_json(auth)
    except Exception as e:
        logging.error(f"User {username}: Error: {e}")
        return

    if values.DryRun is True:
        logging.info(f'User {username}: Dry run ')
    else:
        # Build the resource name of the parent secret.
        try: 
            parent_access = client.secret_path(key_args.get('project_id'), key_args.get('key_name'))

            payload_access = values.access_keys[username][0].encode('UTF-8')
            print(parent_access, payload_access)
            data_access = {"parent": parent_access, "payload": {"data": payload_access}}
            response = client.add_secret_version(request=data_access)
            logging.debug(f"User {username}: Response: {response}")
        except Exception as e:
            logging.error(f"User {username}: Exception trying to update Google Access Key - Key may need to be updated manually. Exception: {e}")
            return
        try: 
            parent_secret = client.secret_path(key_args.get('project_id'), key_args.get('key_secret'))
            payload_secret = values.access_keys[username][1].encode('UTF-8')
            data_secret = {"parent": parent_secret, "payload": {"data": payload_secret}}
            response = client.add_secret_version(request=data_secret)
            logging.debug(f"User {username}: Response: {response}")
        except Exception as e:
            logging.error(f"User {username}: Exception trying to update Google Secret Key - Key may need to be updated manually. Exception: {e}")
            return

        logging.info(f"User {username}: Access key and Secret key written to Secret Manager")
        pass


def wait_for_operation(username, compute, project, region, operation):
    logging.info(f"User {username}: Starting rolling update for {project}")
    while True:
        result = compute.regionOperations().get(
            project=project,
            region=region,
            operation=operation).execute()

        if result['status'] == 'DONE':
            logging.info(f'User {username}: Done')
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(5)


def rotate_instance_groups(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['client_cred']
    regions = key_args.get('regions')
    rotate_gcp_instance_group(username, auth, regions, 2)


def rotate_fg_instance_groups(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['fg_cred']
    regions = key_args.get('regions')
    rotate_gcp_instance_group(username, auth, regions, 3)


def rotate_gcp_instance_group(username, auth, regions, max_unavailable):
    credentials = service_account.Credentials.from_service_account_file(auth)
    # authenticate with compute api
    try:
        compute = build('compute', 'v1', credentials=credentials)
    except Exception as e:
        logging.error(f"User {username}: Exception trying to authenticate with google: {e}")
        return
    logging.debug("Authorized")
    for item in regions:
        region = list(item)[0]
        project = item[region]['project']

        # Get the instance group - assuming only one group per region
        try:
            instance_group_list = compute.regionInstanceGroups().list(project=project, region=region).execute()
            instance_group = instance_group_list['items'][0]['name']
        except Exception as e:
            logging.error(f"User {username}: Unable to retrieve intsance group: {e}")
            return
        logging.debug(f"User {username}: Project: {project} Instance_group {instance_group} Region {region}")

        # retrieve instance template in use from project (this case is 1 regional instance manager in project)
        try:
            project_list = compute.regionInstanceGroupManagers().list(
                project=project,
                region=region).execute()
            instance_template = project_list['items'][0]['versions'][0]['instanceTemplate']
        except Exception as e:
            logging.error(f"User {username}: Unable to retrieve current instance template: {e}")
            return 
        logging.debug(f"User {username}: template: {project_list['items'][0]['versions'][0]['instanceTemplate']}")
        # set version to current datetime
        version = str(datetime.now())
        # create body for patch update
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

        if values.DryRun:
            logging.info(f"User {username}: Dry run. Instance group {instance_group} will not be rotated.")
            return

        # run rolling update to get new keys
        try:
            operation = compute.regionInstanceGroupManagers().patch(
                project=project,
                region=region,
                instanceGroupManager=instance_group,
                body=body).execute()
            wait_for_operation(username, compute, project, region, operation['name'])
        except Exception as e:
            logging.error(f"User {username}: Unable to update instance group: {e}")
            return


def update_encrypted_secret(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['fg_cred']
    # Create the kms client.
    try:
        credentials = service_account.Credentials.from_service_account_file(auth)
    except Exception as e:
        logging.error(f"User {username}: Error: {e}")
        return

    if values.DryRun is True:
        logging.info(f'User {username}: Dry run ')
    else:

        try:
            kms_client = kms_v1.KeyManagementServiceClient(credentials=credentials)
            storage_client = storage.Client(key_args.get('project_id'), credentials=credentials)

        except Exception as e:
            logging.error(f"User {username}: Exception trying to update flight-gateway cred - Key may need to be updated manually. Exception: {e}")
            return
        # Value='New Key Id: ' + values.access_key[0]+' New Secret Key: '+values.access_key[1]
        # print(Value)

        # create aws file with new credential from the ../config/aws/credentials
        aws_cred = ("[default]\naws_access_key_id = {0}\naws_secret_access_key = {1}\n".
                    format(values.access_keys[username][0], values.access_keys[username][1]))

        # encrypt that file through kms
        try:
            aws_cred_encrypted = encrypt_symmetric(kms_client, key_args.get('project_id'),
                                                   key_args.get('key_ring_location'),
                                                   key_args.get('key_ring_id'),
                                                   key_args.get('key_id'), aws_cred)
        except Exception as e:
            logging.error(f"User {username}: Exception trying to encrypt flight-gateway cred Exception: {0}")
            return

        temp_dir = tempfile.gettempdir()
        encrypted_filename = 'aws.credentials.encrypted'
        encrypted_file_path = os.path.join(temp_dir, encrypted_filename)

        with open(encrypted_file_path, "wb") as file_handle:
            file_handle.write(aws_cred_encrypted)

        try:
            # save that file to the storage under gcp path /project/flight-gateway/storage/...
            upload_blob(username, storage_client, key_args.get('bucket_name'), encrypted_file_path, key_args.get('file_name'))
        except Exception as e:
            logging.error(f"User {username}: Exception trying to upload encrypted cred to gcp bucket. Exception: {e}")
            return

        # delete local encrypted file.
        os.remove(encrypted_file_path)

        return "Rotate AWS cred in GCP complete"


def encrypt_symmetric(kms_client, project_id, location_id, key_ring_id, key_id, plaintext):
    # Convert the plaintext to bytes.
    plaintext_bytes = plaintext.encode('utf-8')

    # Optional, but recommended: compute plaintext's CRC32C.
    # See crc32c() function defined below.
    plaintext_crc32c = crc32c(plaintext_bytes)

    # Build the key name.
    key_name = kms_client.crypto_key_path(project_id, location_id, key_ring_id, key_id)

    # Initialize request argument(s)
    request = kms_v1.EncryptRequest(
        name=key_name,
        plaintext=plaintext_bytes,
        plaintext_crc32c=plaintext_crc32c
    )

    # Make the request
    encrypt_response = kms_client.encrypt(request=request)

    # Optional, but recommended: perform integrity verification on encrypt_response.
    # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    # https://cloud.google.com/kms/docs/data-integrity-guidelines
    if not encrypt_response.verified_plaintext_crc32c:
        raise Exception('The request sent to the server was corrupted in-transit.')
    if not encrypt_response.ciphertext_crc32c == crc32c(encrypt_response.ciphertext):
        raise Exception('The response received from the server was corrupted in-transit.')
    # End integrity verification
    # print('Ciphertext: {}'.format(encrypt_response.ciphertext))
    return encrypt_response.ciphertext


def crc32c(data):
    """
    Calculates the CRC32C checksum of the provided data.

    Args:
        data: the bytes over which the checksum should be calculated.

    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod
    import six
    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun('crc-32c')
    return crc32c_fun(six.ensure_binary(data))


def upload_blob(username, storage_client, bucket_name, source_file_name, destination_blob_name):
    """Uploads a file to the bucket."""
    # bucket_name = "fgw-deployment-bucket"
    # source_file_name = "local/path/to/file"
    # destination_blob_name = "storage-object-name"

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(destination_blob_name)

    blob.upload_from_filename(source_file_name)

    logging.info(f"User {username}: File {source_file_name} uploaded to {destination_blob_name}.")
