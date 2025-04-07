import logging
import pprint
import boto3
import time
from project import values


def get_ec2_client(configMap, **key_args):
    if values.profile is not None:

        session = get_iam_e_session(**key_args)
        return session.client('ec2')
    else:
        return boto3.client('ec2', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def get_iam_e_session(**key_args):
    return boto3.Session(profile_name=values.profile, region_name=key_args.get('region'))

def get_elb_client(configMap, **key_args):
    if values.profile is not None:
        session = get_iam_e_session(**key_args)
        return session.client('elbv2')
    else:
        if key_args.get('region'):
            return boto3.client('elbv2', aws_access_key_id=configMap['Global']['id'],
                                aws_secret_access_key=configMap['Global']['secret'], region_name=key_args.get('region'))
        else:
            return boto3.client('elbv2', aws_access_key_id=configMap['Global']['id'],
                                aws_secret_access_key=configMap['Global']['secret'])


def list_instances(username, client, instance_name):
    instance_IDs = []
    response = client.describe_instances()
    for instance in response.get('Reservations'):
        if instance.get('Instances')[0].get('State').get('Name') == 'running':
            instance = instance.get('Instances')[0]
            try:
                for name in instance.get('Tags'):
                        if name.get('Key') == 'Name':
                            if instance_name in name.get('Value'):
                                instanceName = name.get('Value')
                                instance_IDs.append(instance.get('InstanceId'))
                                #print(instanceName + " Instance ID: " + instance.get('InstanceId'))
            except:
                pass
    logging.debug(f'User {username}: Found the following instances with Name %s: %s' % (instance_name, str(instance_IDs)))
    return instance_IDs


def terminate_instance_id(username, client, instance_id):
    response = client.terminate_instances(InstanceIds=[instance_id],)
    logging.info(f'User {username}: %s instance terminating' % instance_id)


def get_instance_status(client, instance_id):
    response = client.describe_instances(InstanceIds=[instance_id])
    pprint.pprint(response.get('Reservations')[0].get('Instances'))


def get_describe_instance_status(client, instance_id):
    response = client.describe_instance_status(InstanceIds=[instance_id])
    return(response.get('InstanceStatuses')[0].get('InstanceStatus').get('Details')[0].get('Status'))


def terminate_instances(configMap, username, **key_args):

    elb_client = get_elb_client(configMap, **key_args)
    ec2_client = get_ec2_client(configMap, **key_args)

    instance_names = key_args.get('instances')

    for instance_name in instance_names:
        logging.info(f'User {username}: Terminating instances for %s' % instance_name)
        tg_arn = get_target_group_arn(elb_client, instance_name)
        instances = list_instances(username, ec2_client, instance_name)
        logging.info(f'User {username}: Found following instances: %s' % str(instances))
        growing_instance_list = instances  # list grows as more instances are terminated and new ones are generated
        new_instances = []
        for instance_id in instances:
            reachable = False

            if values.DryRun is True:
                logging.info(f'User {username}: Dry run instance: %s %s' %(instance_name, instance_id))
            else:
                # Remove instance from loadbalancer
                logging.info(f'User {username}: Removing %s from Targetgroup' % instance_id)
                if not _remove_instance_from_targetgroup(elb_client, tg_arn, instance_id):
                    logging.warning(f'User {username}: Failed to remove instance from target group')
                else:
                    logging.info(f'User {username}: Successfully removed %s from Targetgroup - pausing for 60 seconds' % instance_id)
                # Pause for 60 seconds while connections drain on the instance
                time.sleep(60)
                logging.info(f'User {username}: Terminating instance %s' % instance_id)
                terminate_instance_id(username, ec2_client, instance_id)
                while not reachable:
                    checkinstancelist = list_instances(username, ec2_client, instance_name)
                    # print(len(checkinstancelist), len(growing_instance_list))
                    if len(checkinstancelist) > 0:
                        new_instance_ids = list(set(checkinstancelist))
                        for inst in new_instance_ids:
                            if inst not in new_instances and inst not in instances:
                                new_instances.append(inst)
                                logging.info(f'User {username}: Found newly launched instance: %s' % inst)

                        for new_inst in new_instances:
                            instance_reachability = get_describe_instance_status(ec2_client, new_inst)
                            # print(instance_reachability)
                            if instance_reachability == "passed":
                                reachable = True
                                growing_instance_list = checkinstancelist
                                # check load balancer
                                # logging.info('waiting 200 seconds for app to start...')
                                if not _is_instance_inService(elb_client, tg_arn, new_inst):
                                    logging.info(f'User {username}: Waiting for instance %s to be InService...' % new_inst)
                                    time.sleep(45)
                                    while not _is_instance_inService(elb_client, tg_arn, new_inst):
                                        logging.info(f'User {username}: Waiting for instance %s to be InService...' % new_inst)
                                        time.sleep(45)
                                else:
                                    logging.info(f'User {username}: New instance %s is InService - move on' % new_inst)
                    if not reachable:
                        if len(new_instances) < 1:
                            logging.info(f'User {username}: Waiting for newly launched instance(s)...')
                        else:
                            logging.info(f'User {username}: Waiting for newly launched instance to pass status checks...')
                        time.sleep(45)
    # pass


def get_loadbalancername(configMap, instance_name, client, **key_args):

    response = client.describe_load_balancers()

    list_loadbalancers = response.get('LoadBalancerDescriptions')
    for loadbalancer in list_loadbalancers:
        # loadbalancer_names.append(loadbalancer.get('LoadBalancerName'))
        balancer_tags = client.describe_tags(LoadBalancerNames=[loadbalancer.get('LoadBalancerName')])
        tags = balancer_tags.get('TagDescriptions')[0].get('Tags')
        for tag in tags:
            if tag.get('Value') == instance_name:
                return loadbalancer.get('LoadBalancerName')


def get_target_group_arn(client, instance_name):
    response = client.describe_load_balancers()
    list_loadbalancers = response.get('LoadBalancers')
    for loadbalancer in list_loadbalancers:
        list_tgs = client.describe_target_groups(LoadBalancerArn=loadbalancer.get('LoadBalancerArn'))
        for targetgroup in list_tgs.get('TargetGroups'):
            targetgroup_tags = client.describe_tags(ResourceArns=[targetgroup.get('TargetGroupArn')])
            tags = targetgroup_tags.get('TagDescriptions')[0].get('Tags')
            for tag in tags:
                if tag.get('Value') == instance_name:
                    return targetgroup.get('TargetGroupArn')


def _remove_instance_from_loadbalancer(elb_client, elb_name, instance_id):
    response = elb_client.deregister_instances_from_load_balancer(
        LoadBalancerName=elb_name,
        Instances=[
            {
                'InstanceId': instance_id
            },
        ]
    )
    return response.get('ResponseMetadata').get('HTTPStatusCode') == 200


def _remove_instance_from_targetgroup(elb_client, tg_arn, instance_id):
    response = elb_client.deregister_targets(
        TargetGroupArn=tg_arn,
        Targets=[
            {
                'Id': instance_id
            },
        ]
    )
    return response.get('ResponseMetadata').get('HTTPStatusCode') == 200


##
def _is_instance_inService_old(elb_client,elb_name, instance_id):
    response = elb_client.describe_instance_health(
                        LoadBalancerName=elb_name,
                        Instances=[
                            {
                                'InstanceId': instance_id
                            },
                        ]
                    )
    return response.get('InstanceStates')[0].get('State') =='InService'


def _is_instance_inService(elb_client, tg_arn, instance_id):

    response = elb_client.describe_target_health(TargetGroupArn=tg_arn,
                                                Targets=[
                                                    {
                                                        'Id': instance_id
                                                    }
                                                ]
                                            )
    return response.get('TargetHealthDescriptions')[0].get('TargetHealth').get('State')=='healthy'
