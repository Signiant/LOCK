# written by K. Haggerty
from project import values
from project.plugins.iam import get_iam_session

import boto3
import logging.handlers
import time


def handle_eb_update(config_map, username, **key_args):

    # Need to update the dcrp beanstalks
    result = rotate_dcrp_credentials(
        username,
        values.access_keys[username][0],
        values.access_keys[username][1],
        key_args,
        config_map,
    )
    if result:
        logging.info("Successfully updated ACCESS KEY for %s" % username)
    else:
        logging.error("Failed to update ACCESS KEY for %s" % username)


def rotate_dcrp_credentials(
    username, access_key_id, secret_access_key, key_args, config_map
):
    result = True
    logging.info(
        f"User {username}: Updating credentials for " + key_args.get("app_name")
    )
    app_name = key_args.get("app_name")
    environments = key_args.get("environments")

    eb = get_eb_client(config_map)

    for environment_name in environments:
        logging.info(f"User {username}: Updating %s" % environment_name)
        options = [
            {
                "OptionName": "AWS_ACCESS_KEY_ID",
                "Namespace": key_args.get("namespace"),
                "Value": access_key_id,
            },
            {
                "OptionName": "AWS_SECRET_KEY",
                "Namespace": key_args.get("namespace"),
                "Value": secret_access_key,
            },
        ]
        _update_beanstalk_environment(username, app_name, environment_name, options, eb)
        retries = 0
        while not _is_eb_healthy(app_name, environment_name, eb):
            logging.info(
                f"User {username}: Waiting for EB environment to finish updating..."
            )
            time.sleep(30)
            retries += 1
            if retries > 120:
                logging.warn(
                    f"User {username}: Gave up waiting for environment to finishing updating - moving on"
                )
                result = False
                break
    return result


def _is_eb_healthy(app_name, environment, eb):
    query_result = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[environment]
    )
    if "Environments" in query_result:
        environment = query_result["Environments"][0]
        if environment["Status"] == "Ready" and environment["Health"] == "Green":
            return True
    return False


def _update_beanstalk_environment(username, app_name, env_name, options, eb):
    if values.DryRun is True:
        logging.info(
            f"User {username}: Dry run: _update_beanstalk_environment; "
            + app_name
            + ", "
            + env_name
        )
    else:
        eb.update_environment(
            ApplicationName=app_name, EnvironmentName=env_name, OptionSettings=options
        )
    return True


def get_eb_client(config_map):
    if values.profile is not None:
        session = get_iam_session()
        return session.client("elasticbeanstalk")
    else:
        return boto3.client(
            "elasticbeanstalk",
            aws_access_key_id=config_map["Global"]["id"],
            aws_secret_access_key=config_map["Global"]["secret"],
        )
