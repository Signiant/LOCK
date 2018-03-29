# written by K. Haggerty
import time
import logging.handlers
import boto3
from project import values
from project.plugins.iam import get_iam_session


def handle_eb_update(configMap, username, **key_args):

        # Need to update the dcrp beanstalks
        result = rotate_dcrp_credentials(values.access_key[0], values.access_key[1], key_args,configMap)
        if result:
            logging.info('Successfully updated ACCESS KEY for %s' % username)
        else:
            logging.error('Failed to update ACCESS KEY for %s' % username)


def rotate_dcrp_credentials(access_key_id, secret_access_key, key_args, configMap):
    result = True
    logging.info('Updating credentials for '+key_args.get('app_name'))
    app_name = key_args.get('app_name')
    environments = key_args.get('environments')

    EB = get_EB_client(configMap)

    for environment_name in environments:
        logging.info('   Updating %s' % environment_name)
        options = []
        options.append({'OptionName': 'AWS_ACCESS_KEY_ID', 'Namespace': key_args.get('namespace'), 'Value': access_key_id})
        options.append({'OptionName': 'AWS_SECRET_KEY', 'Namespace': key_args.get('namespace'), 'Value': secret_access_key})
        _update_beanstalk_environment(app_name, environment_name, options, EB)
        retries = 0
        while not _is_eb_healthy(app_name, environment_name, EB):
            logging.info("Waiting for EB environment to finish updating...")
            time.sleep(30)
            retries += 1
            if retries > 120:
                logging.warn("Gave up waiting for environment to finishing updating - moving on")
                result = False
                break
    return result


def _is_eb_healthy(app_name, environment, EB):
    query_result = EB.describe_environments(ApplicationName=app_name,
                                            EnvironmentNames=[environment])
    if 'Environments' in query_result:
        environment = query_result['Environments'][0]
        if environment['Status'] == 'Ready' and environment['Health'] == 'Green':
            return True
    return False


def _update_beanstalk_environment(app_name, env_name, options, EB):
    if values.DryRun is True:
        logging.info('Dry run: _update_beanstalk_environment; ' +app_name +", "+ env_name)
    else:
        EB.update_environment(ApplicationName=app_name,
                              EnvironmentName=env_name,
                              OptionSettings=options)
    return True


def get_EB_client(configMap):
    if values.profile is not None:
        session = get_iam_session()
        return session.client('elasticbeanstalk')
    else:
        return boto3.client('elasticbeanstalk', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])