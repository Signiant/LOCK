import boto3
from boto3.s3.transfer import S3Transfer

from project import values


def get_s3_client(configMap):
    return boto3.client('s3', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def update_s3_file(configMap, username, **key_args):

    bucket = key_args.get("bucket")
    file_path = key_args.get("file_path")
    file_name = key_args.get("file_name")
    client = get_s3_client(configMap)

    texts=[]
    texts.append(key_args.get('access_key').replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1]))
    texts.append(key_args.get('secret_key').replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1]))

    response = client.get_object(Bucket=bucket, Key=file_path)

    with open(file_name, 'w') as newfile:
        for text in texts:
            newfile.write(text +"\n")


    s3 = boto3.resource('s3', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])

    transfer = S3Transfer(client)
    #file on disk, bucket name, file dest path in bucket
    transfer.upload_file(file_name, bucket, file_path)





