import logging
import boto3
import sys
import pytz
from project import values
from datetime import datetime
import time

logging.getLogger('botocore').setLevel(logging.CRITICAL)


def get_iam_session():
    return boto3.Session(profile_name=values.profile)

def get_iam_client(configMap,  **kwargs):
    if kwargs.get('credential_profile') != None:
        session = boto3.Session(profile_name=kwargs.get('credential_profile'))
        return session.client('iam')
    elif values.profile is not None:
        session = get_iam_session()
        return session.client('iam')
    else:
        return boto3.client('iam', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])

def delete_older_key(configMap, username, client):  # Delete the key if both have been used
    keys = get_access_keys(client, username)
    if len(keys) > 1:
        keyid1 = keys[0].get('AccessKeyId')
        keyid2 = keys[1].get('AccessKeyId')

        key1 = client.get_access_key_last_used(AccessKeyId=keyid1)
        key2 = client.get_access_key_last_used(AccessKeyId=keyid2)

        if key2.get('AccessKeyLastUsed').get('LastUsedDate') is not None and key1.get('AccessKeyLastUsed').get('LastUsedDate') is not None:
            if key2.get('AccessKeyLastUsed').get('LastUsedDate') > key1.get('AccessKeyLastUsed').get('LastUsedDate') :
                delete_prompt(configMap, username, client, keyid1)
            elif key2.get('AccessKeyLastUsed').get('LastUsedDate') < key1.get('AccessKeyLastUsed').get('LastUsedDate'):
                delete_prompt(configMap, username, client, keyid2)

def delete_prompt(configMap, username,client,key):
    list_keys(configMap, username,client)
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}
    #  logging.info('Delete the access old key? (y/n) ' + (keys[1].get('AccessKeyId') if n == 0 else keys[0].get('AccessKeyId')))
    choice = None
    while choice not in yes and choice not in no:
        time.sleep(1)

        choice = input('There are 2 keys. Delete the old access key: % ? (y/n) \n' % key)
        if choice in yes:
            delete_old_key(client, username, key)
            logging.info("      "+username + ': Old key deleted')
        elif choice in no:
            logging.info('      Key was not deleted.')
            sys.exit()

def create_and_test_key(configMap, username):  # TO TEST A KEY
    client = get_iam_client(configMap)
    response = client.create_access_key(UserName=username)

    import time
    logging.info('Waiting for key to populate...')
    time.sleep(15)

    client2 =boto3.client('iam', aws_access_key_id=response.get('AccessKey').get('AccessKeyId'),
                                 aws_secret_access_key=response.get('AccessKey').get('SecretAccessKey'))

    response = client2.list_access_keys(UserName=username)
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
            logging.info('      '+username + " inactive key deleted.")



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
    if values.access_key == ("", "") and values.DryRun is False:  # run only if user hasnt manually entered a key
        from project.main import update_access_key

        # setup connection
        client = get_iam_client(configMap,  **kwargs)

        # get existing keys
        oldkeys = get_access_keys(client, username)

        # delete 'inactive' keys and keys that have never been used (if any)
        delete_inactive_key(client, oldkeys, username)
        delete_older_key(configMap, username, client)
        # create a new key
        new_key = create_key(client, username)
        logging.info('      New key created for user ' + username)
        update_access_key(new_key)
        if values.hide_key is True:
            print('                           New AccessKey: ' + str(new_key[0]))
        else:
            print('                           New AccessKey: ' + str(new_key))
        return new_key
    else:
        logging.info('Dry run of get new key')


# validate that new key is being used and delete the old unused key otherwise do nothing and advise the user
def validate_new_key(configMap, username):

    client = get_iam_client(configMap)
    keys = get_access_keys(client, username)

    lastUsed = []
    for key in keys:
        response = key_last_used(client, key.get('AccessKeyId'))
        lastUsed.append(response)

    if len(keys)>1:
        if keys[0].get('CreateDate') > keys[1].get('CreateDate'):  # get the most recently created key
            lastused = lastUsed[0].get('AccessKeyLastUsed').get('LastUsedDate')  # get the most recently created key's last used date
            old_key_use_date = lastUsed[1].get('AccessKeyLastUsed').get('LastUsedDate')
            n = 0
        elif keys[1].get('CreateDate') > keys[0].get('CreateDate'):
            lastused = lastUsed[1].get('AccessKeyLastUsed').get('LastUsedDate')
            old_key_use_date = lastUsed[0].get('AccessKeyLastUsed').get('LastUsedDate')
            n = 1

        present = datetime.now()
        present = pytz.utc.localize(present)

        timediff = old_key_use_date - present
        print('')

        if (timediff.seconds / 3600) < configMap['Global']['key_validate_time_check']:
            logging.info('Old access key was used %s days and %.1f hours ago.' % (str((timediff.days)).replace('-',''), timediff.seconds/3600))
        logging.info("New key has not been used. Check if service is properly running or if the key is properly assigned to the service.")

        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}
        choice = None
        while choice not in yes and choice not in no:

            keyname=(keys[1].get('AccessKeyId') if n == 0 else keys[0].get('AccessKeyId'))
            choice = input('Delete the old access key:'+ keyname +'? (y/n) \n' ).lower()
            if choice in yes:
                if n == 0:
                    delete_old_key(client, username, keys[1].get('AccessKeyId'))
                else:
                    delete_old_key(client, username, keys[0].get('AccessKeyId'))
                logging.info('      '+username + ': Old key deleted.')
            elif choice in no:
                logging.info('Key was not deleted.')
    else:
        logging.info('Only one key available.')


def delete_iam_user(configMap, username, **key_args):
    client = get_iam_client(configMap)
    client.delete_user(
        UserName=username
    )


def list_keys(configMap, username, client):
    keys = get_access_keys(client, username)
    for key in keys:
        response = (key_last_used(client,key.get('AccessKeyId')))
        key["Last Used"] = response.get('AccessKeyLastUsed').get('LastUsedDate')
        print('')
        for i in key:
            logging.info(i + ': ' + str(key[i]))


def rotate_ses_smtp_user(configMap, username,  **key_args):

    client = get_iam_client(configMap)
    if values.DryRun is True:
        logging.info('Dry run : rotate_ses_smtp_user')
    else:
        try:
            response = client.list_access_keys(UserName=username)
            keys = response.get('AccessKeyMetadata')
            for key in keys:
                try:
                    response = client.delete_access_key(
                        UserName=username,
                        AccessKeyId=key.get('AccessKeyId')
                    )
                except:
                    pass
        except:
            pass
        try:
            client.detach_user_policy(UserName=username, PolicyArn=key_args.get('policy_arn'))
        except:
            pass
        delete_iam_user(configMap, username, **key_args)

        client.create_user(UserName=username)
        client.attach_user_policy(UserName=username, PolicyArn=key_args.get('policy_arn'))
        key = create_key(client, username)
        print('                           New AccessKey: ' + str(key))

        password = hash_smtp_pass_from_secret_key(key[1])

        user_password = (key[0], password)
        update_user_password(user_password)
        logging.info('      '+username + ' new user and password created')


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
    client = get_ssm_client(configMap)

    # NOTE that this is the user/password, the secret key is NOT a regular secret key, while username is the Accesskey
    if values.DryRun is True:
        logging.info('Dry run: store_key_parameter_store')
    else:
        client.put_parameter(
            Name='LOCK.'+username.upper(),
            Description='modified by LOCK',
            Value='Username: ' + values.user_password[0] + ' Password: ' + values.user_password[1].decode("utf-8"),
            Type='SecureString',
            KeyId=configMap['Global']['parameter_store']['KeyId'],
            Overwrite=True
        )
        logging.info('      '+username + ' username and password written to parameter store.')


def store_key_parameter_store(configMap, username,  **key_args):

    client = get_ssm_client(configMap, **key_args)
    if values.DryRun is True:
        logging.info('Dry run: store_key_parameter_store')
    else:
        client.put_parameter(
            Name='LOCK.'+username.upper(),
            Description='modified by LOCK',  # config desc
            Value='Key Id: ' + values.access_key[0]+' Secret Key: '+values.access_key[1],  # Key ID: XXXXXX Secret Key: XXXX
            Type='SecureString',
            KeyId=configMap['Global']['parameter_store']['KeyId'],
            Overwrite=True
        )
        logging.info('      '+username+' key written to parameter store.')


def update_user_password(pw):
    from project import values
    values.user_password = pw

def get_ssm_client(configMap, **key_args):
    if values.profile is not None:
        session = get_iam_session()
        return session.client('ssm')
    else:
        return boto3.client('ssm', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])
