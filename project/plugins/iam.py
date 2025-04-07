from botocore.exceptions import ClientError
from project import values
from datetime import datetime, timezone

import base64
import boto3
import hashlib
import hmac
import logging
import pytz
import sys
import time

logging.getLogger("botocore").setLevel(logging.CRITICAL)


def get_iam_session():
    return boto3.Session(profile_name=values.profile)


def get_iam_client(config_map, **kwargs):
    if kwargs.get("credential_profile") is not None:
        profile_name = kwargs.get("credential_profile")
        session = boto3.Session(profile_name=profile_name)
        return session.client("iam")
    elif values.profile is not None:
        session = get_iam_session()
        return session.client("iam")
    else:
        return boto3.client(
            "iam",
            aws_access_key_id=config_map["Global"]["id"],
            aws_secret_access_key=config_map["Global"]["secret"],
        )


def delete_older_key(
    config_map, username, client
):  # Delete the key if both have been used
    keys = get_access_keys(client, username)
    if len(keys) > 1:
        keyid1 = keys[0].get("AccessKeyId")
        keyid2 = keys[1].get("AccessKeyId")

        key1 = client.get_access_key_last_used(AccessKeyId=keyid1)
        key2 = client.get_access_key_last_used(AccessKeyId=keyid2)

        delete_special = False

        if (
            key2.get("AccessKeyLastUsed").get("LastUsedDate") is not None
            and key1.get("AccessKeyLastUsed").get("LastUsedDate") is not None
        ):
            if key2.get("AccessKeyLastUsed").get("LastUsedDate") > key1.get(
                "AccessKeyLastUsed"
            ).get("LastUsedDate"):
                delete_prompt(config_map, username, client, keyid1, delete_special)
            elif key2.get("AccessKeyLastUsed").get("LastUsedDate") < key1.get(
                "AccessKeyLastUsed"
            ).get("LastUsedDate"):
                delete_prompt(config_map, username, client, keyid2, delete_special)
            else:
                delete_special = True
                delete_prompt(config_map, username, client, keyid2, delete_special)


def delete_prompt(config_map, username, client, key, delete_special):
    list_keys(config_map, username)
    yes = {"yes", "y", "ye", ""}
    no = {"no", "n"}
    choice = None
    while choice not in yes and choice not in no:
        time.sleep(1)
        if delete_special:
            choice = input(
                "There are 2 keys that were created at the same time. Delete the 2nd access key: %s ? (y/n) \n"
                % key
            )
        else:
            choice = input(
                "There are 2 keys. Delete the old access key: %s ? (y/n) \n" % key
            )
        if choice in yes:
            client.delete_access_key(UserName=username, AccessKeyId=key)
            logging.info(f"User {username}: Old key deleted")
        elif choice in no:
            logging.info(f"User {username}: Key was not deleted.")
            sys.exit()


def create_and_test_key(config_map, username):  # TO TEST A KEY
    client = get_iam_client(config_map)
    response = client.create_access_key(UserName=username)

    import time

    logging.info(f"User {username}: Waiting for key to populate...")
    time.sleep(15)

    client2 = boto3.client(
        "iam",
        aws_access_key_id=response.get("AccessKey").get("AccessKeyId"),
        aws_secret_access_key=response.get("AccessKey").get("SecretAccessKey"),
    )

    response = client2.list_access_keys(UserName=username)
    print(response)


def get_access_keys(client, username):  # list of dictionary key metadata
    try:
        response = client.list_access_keys(UserName=username)
        return response.get("AccessKeyMetadata")
    except ClientError as e:
        logging.error(f"User {username}: {e}")
        return None


def delete_inactive_key(client, keys, username):
    for key in keys:
        response = key_last_used(client, key.get("AccessKeyId"))
        date = response.get("AccessKeyLastUsed").get("LastUsedDate")
        if key.get("Status") == "Inactive":
            client.delete_access_key(
                UserName=username, AccessKeyId=key.get("AccessKeyId")
            )
            logging.info(
                f"User {username}: inactive key (%s) deleted" % key.get("AccessKeyId")
            )
        if date is None and key.get("Status") != "Inactive":
            logging.warning(
                f"User {username}: There appears to be a key (%s) that is not being used"
                % key.get("AccessKeyId")
            )


def create_key(client, username):
    try:
        response = client.create_access_key(UserName=username)
        return response.get("AccessKey").get("AccessKeyId"), response.get(
            "AccessKey"
        ).get("SecretAccessKey")
    except Exception as e:
        logging.error(f"User {username}: Unable to create new key: {e}")
        return None, None


def delete_old_key(user_data, config_map, username, key_id, prompt):
    iam_data = user_data.get("plugins")[0].get("iam")[0].get("get_new_key")
    aws_profile = None
    if iam_data:
        if "credential_profile" in iam_data:
            aws_profile = iam_data.get("credential_profile")
    if aws_profile:
        kwargs = {"credential_profile": aws_profile}
        client = get_iam_client(config_map, **kwargs)
    else:
        client = get_iam_client(config_map)

    deletion_prompt = (
        prompt + "\n" + "   Delete the old access key: " + key_id + "? (y/n) "
    )
    yes = {"yes", "y", "ye", ""}
    no = {"no", "n"}
    choice = None
    while choice not in yes and choice not in no:

        choice = input(deletion_prompt).lower()
        if choice in yes:
            if values.DryRun:
                logging.info(f"User {username}: Dry run. {key_id} was not deleted.")
            else:
                client.delete_access_key(UserName=username, AccessKeyId=key_id)
                logging.info(f"User {username}: Old key deleted.")
        elif choice in no:
            logging.info(f"User {username}: Key was not deleted.")


def key_last_used(client, key_id):
    return client.get_access_key_last_used(AccessKeyId=key_id)


def get_new_key(config_map, username, **kwargs):
    if (
        values.access_keys[username] == ("", "") and values.DryRun is False
    ):  # run only if user hasn't manually entered a key
        from project.main import update_access_key

        # setup connection
        client = get_iam_client(config_map, **kwargs)
        # get existing keys
        existing_keys = get_access_keys(client, username)
        # delete 'inactive' keys (and warn about unused active keys)
        delete_inactive_key(client, existing_keys, username)
        # Get the keys again
        existing_keys = get_access_keys(client, username)
        if len(existing_keys) < 2:
            # create a new key
            new_key = create_key(client, username)
            logging.info(f"User {username}: New key created for user")
            update_access_key(username, new_key)
            # TODO: Print secret key to log file even if hide_key is provided
            if values.hide_key is True:
                logging.info(f"User {username}: New AccessKey: " + str(new_key[0]))
            else:
                logging.info(f"User {username}: New AccessKey: " + str(new_key))
            return new_key
        else:
            # There are still 2 keys present - can't create another one
            logging.error(
                f"User {username}: There are already two (active) keys present - cannot continue. "
                f"Please re-run the script with the 'validate' action for the user '{username}' before "
                f"retrying 'rotate'."
            )
            return None
    else:
        logging.info(f"User {username}: Dry run of get new key.")
        # setup connection
        client = get_iam_client(config_map, **kwargs)
        # get existing keys
        existing_keys = get_access_keys(client, username)

        logging.info(f"User {username}: User has {len(existing_keys)} keys")

        if len(existing_keys) == 1:
            return existing_keys[0]
        else:
            return None


# validate that new key is being used and delete the old unused key otherwise do nothing and advise the user
def validate_new_key(config_map, username, user_data):
    deletion_prompt = f"Key validation results for user: {username}"
    logging.info(f"User {username}: Validating keys for user")

    iam_data = user_data.get("plugins")[0].get("iam")[0].get("get_new_key")
    aws_profile = None
    if iam_data:
        if "credential_profile" in iam_data:
            aws_profile = iam_data.get("credential_profile")
    if aws_profile:
        kwargs = {"credential_profile": aws_profile}
        client = get_iam_client(config_map, **kwargs)
    else:
        client = get_iam_client(config_map)
    keys = get_access_keys(client, username)

    last_used = []
    for key in keys:
        response = key_last_used(client, key.get("AccessKeyId"))
        last_used.append(response)

    if len(keys) > 1:
        new_key_last_used = None
        old_key_use_date = None
        new_key_index = None
        old_key_index = None

        # get the most recently created key
        if keys[0].get("CreateDate") > keys[1].get("CreateDate"):
            # get the most recently created key's last used date
            new_key_last_used = (
                last_used[0].get("AccessKeyLastUsed").get("LastUsedDate")
            )
            old_key_use_date = last_used[1].get("AccessKeyLastUsed").get("LastUsedDate")
            new_key_index = 0
            old_key_index = 1
        elif keys[1].get("CreateDate") > keys[0].get("CreateDate"):
            new_key_last_used = (
                last_used[1].get("AccessKeyLastUsed").get("LastUsedDate")
            )
            old_key_use_date = last_used[0].get("AccessKeyLastUsed").get("LastUsedDate")
            new_key_index = 1
            old_key_index = 0

        present = datetime.now(tz=timezone.utc)
        present = pytz.utc.localize(present)
        logging.debug(f"User {username}: Present time (UTC): %s" % str(present))
        logging.debug(
            f"User {username}: Old key time (UTC): %s" % str(old_key_use_date)
        )

        timediff_hours = None
        if old_key_use_date:
            timediff = present - old_key_use_date
            timediff_hours = (timediff.days * 24) + (timediff.seconds / 3600)
            logging.debug(f"User {username}: timediff: %s" % str(timediff))
            logging.debug(f"User {username}: timdiff (hours): %s" % str(timediff_hours))

        oldkeyname = keys[old_key_index].get("AccessKeyId")
        newkeyname = keys[new_key_index].get("AccessKeyId")

        if old_key_use_date:
            deletion_prompt += "\n" + "   Old key (%s) was last used: %s" % (
                oldkeyname,
                str(old_key_use_date),
            )
            logging.info(
                f"User {username}: Old key (%s) was last used: %s"
                % (oldkeyname, str(old_key_use_date))
            )
            logging.debug(
                f"User {username}: Time diff in hours: %s" % str(timediff_hours)
            )

            if timediff_hours < config_map["Global"]["key_validate_time_check"]:
                deletion_prompt += (
                    "\n"
                    + "      Old key was used less than %s hours ago"
                    % (str(config_map["Global"]["key_validate_time_check"]))
                )
                logging.warning(
                    f"User {username}: Old key was used less than %s hours ago"
                    % (str(config_map["Global"]["key_validate_time_check"]))
                )
        else:
            deletion_prompt += (
                "\n"
                + "   Old key (%s) has not been used. Is it still needed?" % oldkeyname
            )
            logging.warning(
                f"User {username}: Old key (%s) has not been used. Is it still needed?"
                % oldkeyname
            )

        if new_key_last_used is None:
            deletion_prompt += (
                "\n"
                + "   New key (%s) has not been used. Check if service is properly running or if the key is properly assigned to the service."
                % newkeyname
            )
            logging.info(
                f"User {username}: New key (%s) has not been used. Check if service is properly running or if the key is properly assigned to the service."
                % newkeyname
            )
        else:
            deletion_prompt += "\n" + "   New key (%s) was last used: %s" % (
                newkeyname,
                str(new_key_last_used),
            )
            logging.info(
                f"User {username}: New key (%s) was last used: %s"
                % (newkeyname, str(new_key_last_used))
            )

        return oldkeyname, deletion_prompt
    else:
        logging.info(
            f"User {username}: Only one key available - skipping deletion of old key."
        )


def delete_iam_user(config_map, username, **_):
    client = get_iam_client(config_map)
    client.delete_user(UserName=username)


def list_keys(config_map, username):
    key_args = {}
    client = get_iam_client(config_map, **key_args)
    keys = get_access_keys(client, username)
    if keys is not None:
        for key in keys:
            response = key_last_used(client, key.get("AccessKeyId"))
            key["Last Used"] = response.get("AccessKeyLastUsed").get("LastUsedDate")
            for i in key:
                logging.info(f"User {username}: " + i + ": " + str(key[i]))


def rotate_ses_smtp_user(config_map, username, **key_args):
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run: rotate_ses_smtp_user")
    else:
        key = get_new_key(config_map, username, **key_args)
        if key:
            password = hash_smtp_pass_from_secret_key(key[1])

            user_password = (key[0], password)
            update_user_password(user_password)
            logging.info(f"User {username}: new user and password created")
            if values.hide_key is True:
                print(
                    f"                           New Username: {str(user_password[0])}"
                )
            else:
                print(
                    f"                           New Username, Password: {str(user_password)}"
                )
        else:
            logging.error(f"User {username}: Unable to get new key - skipping")


# https://aws.amazon.com/premiumsupport/knowledge-center/ses-rotate-smtp-access-keys/
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def hash_smtp_pass_from_secret_key(secret_access_key, region="us-east-1"):
    date = "11111111"
    service = "ses"
    message = "SendRawEmail"
    terminal = "aws4_request"
    version = 0x04

    signature = sign(("AWS4" + secret_access_key).encode("utf-8"), date)
    signature = sign(signature, region)
    signature = sign(signature, service)
    signature = sign(signature, terminal)
    signature = sign(signature, message)
    signature_and_version = bytes([version]) + signature
    smtp_password = base64.b64encode(signature_and_version)
    return smtp_password.decode("utf-8")


def store_password_parameter_store(config_map, username, **key_args):
    client = get_ssm_client(config_map, **key_args)

    # NOTE that this is the user/password, the secret key is NOT a regular secret key, while username is the Accesskey
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run: store_key_parameter_store")
    else:
        key_id = key_args.get("key", config_map["Global"]["parameter_store"]["KeyId"])

        client.put_parameter(
            Name="LOCK." + username.upper(),
            Description="modified by LOCK",
            Value="Username: "
            + values.user_password[0]
            + " Password: "
            + values.user_password[1],
            Type="SecureString",
            KeyId=key_id,
            Overwrite=True,
        )
        logging.info(
            f"User {username}: username and password written to parameter store."
        )


def store_key_parameter_store(config_map, username, **key_args):
    client = get_ssm_client(config_map, **key_args)
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run: store_key_parameter_store")
    else:
        parameter_name = key_args.get("param_name", "LOCK." + username.upper())
        if key_args.get("value") is not None:
            # value defined by user
            parameter_value = (
                key_args.get("value")
                .replace("<new_key_name>", values.access_keys[username][0])
                .replace("<new_key_secret>", values.access_keys[username][1])
            )
        else:
            # Key ID: XXXXXX Secret Key: XXXX
            parameter_value = (
                "Key Id: "
                + values.access_keys[username][0]
                + " Secret Key: "
                + values.access_keys[username][1]
            )
        if key_args.get("key") is not None:
            key_id = key_args.get("key")
        else:
            key_id = config_map["Global"]["parameter_store"]["KeyId"]
        client.put_parameter(
            Name=parameter_name,
            Description="modified by LOCK",  # config desc
            Value=parameter_value,
            Type="SecureString",
            KeyId=key_id,
            Overwrite=True,
        )
        logging.info(
            f"User {username}: " + parameter_name + " key written to parameter store."
        )


def ecs_task_restart(config_map, username, **key_args):
    """
    restart all tasks in a service by finding the service and restart its tasks
    :param config_map:
    :param username:
    :param key_args:
    :return:
    """
    client = get_ecs_client(config_map, **key_args)
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run: ecs_task_restart")
    else:
        if key_args.get("cluster") is not None:
            cluster_name = key_args.get("cluster")
        else:
            logging.info(f"User {username}: ecs restart failed. cluster not defined")
            return
        if key_args.get("service_wildcard") is not None:
            service_wildcard = key_args.get("service_wildcard")
        else:
            logging.info(
                f"User {username}: ecs restart failed. service_wildcard not defined"
            )
            return
        service_list = client.list_services(cluster=cluster_name)["serviceArns"]

        service_name = None
        for service in service_list:
            if service_wildcard in service:
                service_name = service

        if service_name is None:
            logging.error(
                f"User {username}: ECS restart failed. Unable to retrieve name from list of services."
            )
            return

        print("restart service task for service {0}".format(service_name))
        client.update_service(
            cluster=cluster_name, service=service_name, forceNewDeployment=True
        )
        logging.info(f"User {username}: All tasks for service {service_name} restarted")


def update_user_password(pw):
    from project import values

    values.user_password = pw


def get_ssm_client(config_map, **key_args):
    region_name = key_args.get("region", "us-east-1")

    if key_args.get("credential_profile") is not None:
        profile_name = key_args.get("credential_profile")
        print(profile_name)
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        return session.client("ssm")
    elif values.profile is not None:
        session = get_iam_session()
        return session.client("ssm", region_name=region_name)
    else:
        return boto3.client(
            "ssm",
            aws_access_key_id=config_map["Global"]["id"],
            aws_secret_access_key=config_map["Global"]["secret"],
            region_name=region_name,
        )


def get_ecs_client(config_map, **key_args):
    region_name = key_args.get("region", "us-east-1")

    if key_args.get("credential_profile") is not None:
        profile_name = key_args.get("credential_profile")
        print(profile_name)
        session = boto3.Session(profile_name=profile_name, region_name=region_name)
        return session.client("ecs")
    elif values.profile is not None:
        session = get_iam_session()
        return session.client("ecs", region_name=region_name)
    else:
        return boto3.client(
            "ecs",
            aws_access_key_id=config_map["Global"]["id"],
            aws_secret_access_key=config_map["Global"]["secret"],
            region_name=region_name,
        )
