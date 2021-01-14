import logging
import boto3
from botocore.exceptions import ClientError
import sys
import pytz
from project import values
from datetime import datetime
import time

logging.getLogger('botocore').setLevel(logging.CRITICAL)


def get_iam_session():
    return boto3.Session(profile_name=values.profile)


def get_iam_client(configMap,  **kwargs):
    if kwargs.get('credential_profile') is not None:
        profile_name = kwargs.get('credential_profile')
        session = boto3.Session(profile_name=profile_name)
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

        delete_special = False

        if key2.get('AccessKeyLastUsed').get('LastUsedDate') is not None and key1.get('AccessKeyLastUsed').get('LastUsedDate') is not None:
            if key2.get('AccessKeyLastUsed').get('LastUsedDate') > key1.get('AccessKeyLastUsed').get('LastUsedDate') :
                delete_prompt(configMap, username, client, keyid1, delete_special)
            elif key2.get('AccessKeyLastUsed').get('LastUsedDate') < key1.get('AccessKeyLastUsed').get('LastUsedDate'):
                delete_prompt(configMap, username, client, keyid2, delete_special)
            else:
                delete_special = True
                delete_prompt(configMap, username, client, keyid2, delete_special)


def delete_prompt(configMap, username, client, key, delete_special):
    list_keys(configMap, username)
    yes = {'yes', 'y', 'ye', ''}
    no = {'no', 'n'}
    #  logging.info('Delete the access old key? (y/n) ' + (keys[1].get('AccessKeyId') if n == 0 else keys[0].get('AccessKeyId')))
    choice = None
    while choice not in yes and choice not in no:
        time.sleep(1)
        if delete_special:
            choice = input('There are 2 keys that were created at the same time. Delete the 2nd access key: %s ? (y/n) \n' % key)
        else:
            choice = input('There are 2 keys. Delete the old access key: %s ? (y/n) \n' % key)
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


def get_access_keys(client, username):  # list of dictionary key metadata
    try:
        response = client.list_access_keys(UserName=username)
        return response.get('AccessKeyMetadata')
    except ClientError as e:
        logging.error(e)
        return None


def delete_inactive_key(client, keys, username):
    for key in keys:
        response = key_last_used(client, key.get('AccessKeyId'))
        date = response.get('AccessKeyLastUsed').get('LastUsedDate')
        if key.get('Status') == 'Inactive':
            client.delete_access_key(UserName=username, AccessKeyId=key.get('AccessKeyId'))
            logging.info('  inactive key (%s) deleted' % key.get('AccessKeyId'))
        if date is None and key.get('Status') != 'Inactive':
            logging.warning('There appears to be a key (%s) that is not being used' % key.get('AccessKeyId'))


def create_key(client, username):
    response = client.create_access_key(UserName=username)
    return response.get('AccessKey').get('AccessKeyId'),response.get('AccessKey').get('SecretAccessKey')


def delete_old_key(client, username, keyId):
    return client.delete_access_key(UserName=username, AccessKeyId=keyId)


def key_last_used(client, keyId):
    return client.get_access_key_last_used(
        AccessKeyId=keyId
    )


def get_new_key(configMap, username, **kwargs):
    if values.access_key == ("", "") and values.DryRun is False:  # run only if user hasn't manually entered a key
        from project.main import update_access_key
        # setup connection
        client = get_iam_client(configMap, **kwargs)
        # get existing keys
        existing_keys = get_access_keys(client, username)
        # delete 'inactive' keys (and warn about unused active keys)
        delete_inactive_key(client, existing_keys, username)
        # delete keys that have never been used (if any)
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
def validate_new_key(configMap, username, user_data):
    logging.info('Validating keys for user: %s' % username)

    iam_data = user_data.get('plugins')[0].get('iam')[0].get('get_new_key')
    aws_profile = None
    if iam_data:
        if 'credential_profile' in iam_data:
            aws_profile = iam_data.get('credential_profile')
    if aws_profile:
        kwargs={}
        kwargs['credential_profile']=aws_profile
        client = get_iam_client(configMap, **kwargs)
    else:
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
            new_key_index = 0
            old_key_index = 1
        elif keys[1].get('CreateDate') > keys[0].get('CreateDate'):
            lastused = lastUsed[1].get('AccessKeyLastUsed').get('LastUsedDate')
            old_key_use_date = lastUsed[0].get('AccessKeyLastUsed').get('LastUsedDate')
            new_key_index = 1
            old_key_index = 0

        present = datetime.utcnow()
        present = pytz.utc.localize(present)
        logging.debug('   Present time (UTC): %s' % str(present))
        logging.debug('   Old key time (UTC): %s' % str(old_key_use_date))

        if old_key_use_date:
            timediff = present - old_key_use_date
            timediff_hours = (timediff.days * 24) + (timediff.seconds / 3600)
            logging.debug('   timediff: %s' % str(timediff))
            logging.debug('   timdiff (hours): %s' % str(timediff_hours))

        oldkeyname = keys[old_key_index].get('AccessKeyId')
        newkeyname = keys[new_key_index].get('AccessKeyId')

        if old_key_use_date:
            logging.info('   Old key (%s) was last used: %s' % (oldkeyname,str(old_key_use_date)))
            logging.debug('   Time diff in hours: %s' % str(timediff_hours))

            if timediff_hours < configMap['Global']['key_validate_time_check']:
                logging.warning('      Old key was used less than %s hours ago' % (str(configMap['Global']['key_validate_time_check'])))
        else:
            logging.warning("   Old key (%s) has not been used. Is it still needed?" % oldkeyname)

        if lastused is None:
            logging.info("   New key (%s) has not been used. Check if service is properly running or if the key is properly assigned to the service." % newkeyname)
        else:
            logging.info("   New key (%s) was last used: %s" % (newkeyname, str(lastused)))
        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}
        choice = None
        while choice not in yes and choice not in no:

            choice = input('   Delete the old access key:'+ oldkeyname +'? (y/n) ' ).lower()
            if choice in yes:
                delete_old_key(client, username, keys[old_key_index].get('AccessKeyId'))
                logging.info('      '+username + ': Old key deleted.')
            elif choice in no:
                logging.info('   Key was not deleted.')
    else:
        logging.info('   Only one key available - skipping deletion of old key.')


def delete_iam_user(configMap, username, **key_args):
    client = get_iam_client(configMap)
    client.delete_user(
        UserName=username
    )


def list_keys(configMap, username):
    key_args = {}
    client = get_iam_client(configMap, **key_args)
    keys = get_access_keys(client, username)
    if keys is not None:
        for key in keys:
            response = (key_last_used(client, key.get('AccessKeyId')))
            key["Last Used"] = response.get('AccessKeyLastUsed').get('LastUsedDate')
            print('')
            for i in key:
                logging.info(i + ': ' + str(key[i]))


def rotate_ses_smtp_user(configMap, username, **key_args):
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
    client = get_ssm_client(configMap, **key_args)

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
        if key_args.get('param_name') is not None:
            parameter_name = key_args.get('param_name')
        else:
            parameter_name = 'LOCK.'+username.upper()
        if key_args.get('value') is not None:
            # value defined by user as seen under mediashuttle-support-tool user in conig.yaml
            parameter_value = key_args.get('value').replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>",values.access_key[1])
        else:
            # Key ID: XXXXXX Secret Key: XXXX
            parameter_value = 'Key Id: ' + values.access_key[0]+' Secret Key: '+values.access_key[1]
        if key_args.get('key') is not None:
            key_id = key_args.get('key')
        else:
            key_id = configMap['Global']['parameter_store']['KeyId']
        response = client.put_parameter(
            Name=parameter_name,
            Description='modified by LOCK',  # config desc
            Value=parameter_value,
            Type='SecureString',
            KeyId=key_id,
            Overwrite=True
        )
        print(parameter_name)
        print(response)
        logging.info('      '+parameter_name+' key written to parameter store.')
        param_list = client.describe_parameters(ParameterFilters=[{'Key':'Name','Values':['SIGNIANT.mediashuttle_support_tools']}])
        print(param_list)


def ecs_task_restart(configMap, username,  **key_args):
    """
    restart all tasks in a service by finding the service and restart it's tasks
    :param configMap:
    :param username:
    :param key_args:
    :return:
    """
    client = get_ecs_client(configMap, **key_args)
    if values.DryRun is True:
        logging.info('Dry run: ecs_task_restart')
    else:
        if key_args.get('cluster') is not None:
            cluster_name = key_args.get('cluster')
        else:
            logging.info('ecs restart failed. cluster not defined')
        if key_args.get('service_wildcard') is not None:
            service_wildcard = key_args.get('service_wildcard')
        else:
            logging.info('ecs restart failed. service_wildcard not defined')
        service_list  = client.list_services(cluster=cluster_name)['serviceArns']

        for service in service_list:
            if service_wildcard in service:
                service_name = service
        print("restart service task for service {0}".format(service_name))
        client.update_service(cluster=cluster_name,service=service_name,forceNewDeployment=True)
        logging.info("All tasks for service {0} restarted".format(service_name))


def update_user_password(pw):
    from project import values
    values.user_password = pw


def get_ssm_client(configMap, **key_args):
    if key_args.get('region') is not None:
        region_name = key_args.get('region')
    else:
        region_name = 'us-east-1'
    if key_args.get('credential_profile') is not None:
        profile_name = key_args.get('credential_profile')
        print(profile_name)
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        return session.client('ssm')
    elif values.profile is not None:
        session = get_iam_session()
        return session.client('ssm',region_name=region_name)
    else:
        return boto3.client('ssm', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'],region_name=region_name)

def get_ecs_client(configMap, **key_args):
    if key_args.get('region') is not None:
        region_name = key_args.get('region')
    else:
        region_name = 'us-east-1'
    if key_args.get('credential_profile') is not None:
        profile_name = key_args.get('credential_profile')
        print(profile_name)
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        return session.client('ecs')
    elif values.profile is not None:
        session = get_iam_session()
        return session.client('ecs',region_name=region_name)
    else:
        return boto3.client('ecs', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'],region_name=region_name)