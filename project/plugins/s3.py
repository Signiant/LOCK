import logging
import boto3
import botocore
import os

from project import values
from project.plugins.iam import get_iam_session


def get_s3_client(config_map):
    s3_config = botocore.client.Config(s3={'addressing_style': 'path'})
    if values.profile is not None:
        session = get_iam_session()
        return session.client('s3', config=s3_config)
    else:
        return boto3.client('s3',
                            aws_access_key_id=config_map['Global']['id'],
                            aws_secret_access_key=config_map['Global']['secret'],
                            config=s3_config)


def write_s3_file(config_map, username, **key_args):
    result = False
    bucket = key_args.get("bucket")
    file_path = key_args.get("file_path")
    client = get_s3_client(config_map)

    file_contents = '%s\n%s\n' % (key_args.get('access_key').replace("<new_key_name>", values.access_keys[username][0]),
             key_args.get('secret_key').replace("<new_key_secret>", values.access_keys[username][1]))

    if values.DryRun is True:
        logging.info(f'User {username}: Dry run, upload file %s to s3 bucket %s' % (file_path, bucket))
        result = True
    else:
        try:
            logging.info(f'User {username}: Attempting to upload to s3 bucket %s at path %s' % (bucket, file_path))
            response = client.put_object(Bucket=bucket, Body=file_contents.encode(), Key=file_path)
            if 'ResponseMetadata' in response:
                if 'HTTPStatusCode' in response['ResponseMetadata'] and response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    logging.info(f'User {username}: SUCCESS')
                    result = True
        except:
            logging.critical(f'User {username}: Failed to upload to bucket %d at path %s' % (bucket, file_path))
    return result



