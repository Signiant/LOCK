import logging

import boto3
import os

from project import values
from project.plugins.iam import get_iam_session


def get_s3_client(configMap):
    if values.profile is not None:
        session = get_iam_session()
        return session.client('s3')
    else:
        return boto3.client('s3', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def get_s3_resource(configMap):
    if values.profile is not None:
        session = get_iam_session()
        return session.resource('s3')
    else:
        return boto3.resource('s3', aws_access_key_id=configMap['Global']['id'],
                   aws_secret_access_key=configMap['Global']['secret'])

def write_s3_file(configMap, username, **key_args):

    bucket = key_args.get("bucket")
    file_path = key_args.get("file_path")
    file_name = key_args.get("file_name")
    client = get_s3_client(configMap)

    texts = [key_args.get('access_key').replace("<new_key_name>", values.access_key[0]),
             key_args.get('secret_key').replace("<new_key_secret>", values.access_key[1])]

    with open(file_name, 'w') as newfile:
        for text in texts:
            newfile.write(text + "\n")

    s3 = get_s3_resource(configMap)

    if values.DryRun is True:
        logging.info('Dry run, upload file to s3:')
    else:
        try:
            s3.meta.client.upload_file(file_name, bucket, file_path)
        except:
            logging.error('Failed to upload '+ file_path)


    try:
        os.remove(file_name)
    except OSError:
        pass




