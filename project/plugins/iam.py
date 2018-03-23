
import logging
from datetime import datetime

import boto3
import sys

import time

import pytz

from project import values


def get_iam_client(configMap):
    return boto3.client('iam', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def create_and_test_key(configMap,username):  # TO TEST A KEY
    client = get_iam_client(configMap)
    response = client.create_access_key(UserName=username)

    keyid = response.get('AccessKey').get('AccessKeyId')
    import time
    print('Waiting for key to populate...')
    time.sleep(15)

    client2 =boto3.client('iam', aws_access_key_id=response.get('AccessKey').get('AccessKeyId'),
                                 aws_secret_access_key=response.get('AccessKey').get('SecretAccessKey'))

    response = client2.list_access_keys(UserName=username)
    print(response)
    response = client.get_access_key_last_used(AccessKeyId=keyid)
    print(response)


def get_access_keys(client,username):  # list of dictionary key metadata
    response = client.list_access_keys(UserName=username)
    return response.get('AccessKeyMetadata')


def delete_inactive_key(client, keys, username):
    for key in keys:
        response = key_last_used(client, key.get('AccessKeyId'))
        date = response.get('AccessKeyLastUsed').get('LastUsedDate')
        if (date is None) or (key.get('Status') == 'Inactive'):
            client.delete_access_key(UserName=username, AccessKeyId=key.get('AccessKeyId'))
            logging.critical(username + " inactive key deleted.")


def create_key(client,username):
    response = client.create_access_key(UserName=username)
    return response.get('AccessKey').get('AccessKeyId'),response.get('AccessKey').get('SecretAccessKey')


def delete_old_key(client, username, keyId):
    return client.delete_access_key(UserName=username, AccessKeyId=keyId)


def key_last_used(client, keyId):
    return client.get_access_key_last_used(
        AccessKeyId=keyId
    )


def get_new_key(configMap, username,  **kwargs):
    if values.access_key == ("", ""):  # run only if user hasnt manually entered a key
        from project.main import update_access_key

        # setup connection
        client = get_iam_client(configMap)

        # get existing keys
        oldkeys = get_access_keys(client, username)

        # delete 'inactive' keys and keys that have never been used (if any)
        delete_inactive_key(client, oldkeys, username)

        # create a new key

        new_key = create_key(client, username)
        logging.critical('New key created for user ' + username)
        update_access_key(new_key)
        print('New AccessKey: ' + str(new_key))
        return new_key


# validate that new key is being used and delete the old unused key otherwise do nothing and advise the user
def validate_new_key(configMap, username):

    client = get_iam_client(configMap)
    keys = get_access_keys(client, username)

    lastUsed = []
    for key in keys:
        response = key_last_used(client, key.get('AccessKeyId'))
        lastUsed.append(response)

    if keys[0].get('CreateDate') > keys[1].get('CreateDate'):  # get the most recently created key
        lastused = lastUsed[0].get('AccessKeyLastUsed').get('LastUsedDate')  # get the most recently created key's last used date
        n = 0
    elif keys[1].get('CreateDate') > keys[0].get('CreateDate'):
        lastused = lastUsed[1].get('AccessKeyLastUsed').get('LastUsedDate')
        n = 1

    if lastused is None:
        return "New key has not been used. Check if service is properly running or if the key is properly assigned to the service."
    else:
        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}
        print('Delete old Key (y/n)? ' + (keys[1].get('AccessKeyId') if n == 0 else keys[0].get('AccessKeyId')))
        choice = input().lower()

        if choice in yes:
            if n == 0:
                delete_old_key(client, username, keys[1].get('AccessKeyId'))

            else:
                delete_old_key(client, username, keys[0].get('AccessKeyId'))
            return logging.critical(username + ': new key in use, old key removed.')
        elif choice in no:
            return print('Key was not deleted.')
        else:
            sys.stdout.write("Please respond with 'y' or 'n'")



def delete_iam_user(configMap, username, **key_args):
    client = get_iam_client(configMap)
    client.delete_user(
        UserName=username
    )


def list_keys(configMap, username):
    client = get_iam_client(configMap)
    keys = get_access_keys(client, username)
    for key in keys:
        response = (key_last_used(client,key.get('AccessKeyId')))
        key["Last Used"] = response.get('AccessKeyLastUsed').get('LastUsedDate')
        print('')
        for i in key:
            print(i, ':', key[i])


def rotate_ses_smtp_user(configMap, username,  **key_args):

    client = get_iam_client(configMap)
    try:
        response = client.list_access_keys(UserName=username)
        keys = response.get('AccessKeyMetadata')
        for key in keys:
            response = client.delete_access_key(
                UserName=username,
                AccessKeyId=key.get('AccessKeyId')
            )
        client.detach_user_policy(UserName=username, PolicyArn=key_args.get('policy_arn'))
    except:
        pass
    delete_iam_user(configMap, username, **key_args)

    client.create_user(UserName=username)
    client.attach_user_policy(UserName=username, PolicyArn=key_args.get('policy_arn'))
    key = create_key(client, username)
    print(key)

    password = hash_smtp_pass_from_secret_key(key[1])

    user_password = (key[0], password)
    update_user_password(user_password)
    logging.critical(username + ' new user and password created')


# https://gist.github.com/w3iBStime/a26bd670bf7f98675674
def hash_smtp_pass_from_secret_key(secretkey):
    import base64
    import hmac
    import hashlib

    # replace with the secret key to be hashed
    message = "SendRawEmail"
    sig_bytes = bytearray(b'\x02')  # init with version

    theHmac = hmac.new(secretkey.encode("ASCII"), message.encode("ASCII"), hashlib.sha256)
    the_hmac_hexdigest = theHmac.hexdigest()
    sig_bytes.extend(bytearray.fromhex(the_hmac_hexdigest))
    return base64.b64encode(sig_bytes)


def store_password_parameter_store(configMap, username,  **key_args):
    client = boto3.client('ssm', aws_access_key_id=configMap['Global']['id'], aws_secret_access_key=configMap['Global']['secret'])

   # client.get_parameter(Name=username, WithDecryption=True)

    # NOTE that this is the user/password, the secret key is NOT a regular secret key, while username is the Accesskey
    client.put_parameter(
        Name=username,
        Description='modified by LOCK',
        Value='Username: ' + values.user_password[0] + ' Password: ' + values.user_password[1].decode("utf-8"),
        Type='SecureString',
        Overwrite=True
    )
    logging.critical(username + ' username and password written to parameter store.')


def store_key_parameter_store(configMap, username,  **key_args):

    client = boto3.client('ssm', aws_access_key_id=configMap['Global']['id'],
                          aws_secret_access_key=configMap['Global']['secret'])

    #client.get_parameter(Name=username, WithDecryption=True)

    client.put_parameter(
        Name=username,
        Description='modified by LOCK',  # config desc
        Value='Key Id: ' + values.access_key[0]+' Secret Key: '+values.access_key[1],  # Key ID: XXXXXX Secret Key: XXXX
        Type='SecureString',
        Overwrite=True
    )
    logging.critical(username+' key written to parameter store.')


def update_user_password(pw):
    from project import values
    values.user_password = pw
