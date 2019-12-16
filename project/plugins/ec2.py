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


def list_instances(configMap, instance_name,  **key_args):

    client = get_ec2_client(configMap, **key_args)
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
    logging.debug('    Found the following instances with Name %s: %s' % (instance_name, str(instance_IDs)))
    return instance_IDs


def terminate_instance_id(configMap, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.terminate_instances(InstanceIds=[key_args.get('instance_id')],)
    logging.info('      '+key_args.get('instance_id')+ " instance terminated")


def get_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.describe_instances(InstanceIds=[key_args.get('instance_id')])
    pprint.pprint(response.get('Reservations')[0].get('Instances'))


def get_describe_instance_status(configMap, tg_arn, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.describe_instance_status(InstanceIds=[key_args.get('instance_id')])
    return(response.get('InstanceStatuses')[0].get('InstanceStatus').get('Details')[0].get('Status'))


def terminate_instances(configMap, username,  **key_args):

    elb_client = get_elb_client(configMap, **key_args)

    instance_names = key_args.get('instances')

    for instance_name in instance_names:
        logging.info('  Terminating instance for %s' % instance_name)
        tg_arn = get_target_group_arn(configMap, instance_name, elb_client, **key_args)
        instances = list_instances(configMap, instance_name,  **key_args)
        growing_instance_list = instances  # list grows as more instances are terminated and new ones are generated
        for instanceid in instances:
            reachable = False
            key_args['instance_id'] = instanceid

            if values.DryRun is True:
                logging.info('Dry run instance:'+instance_name + " " + instanceid)
            else:
                # Remove instance from loadbalancer
                logging.info('    Removing %s from Targetgroup' % instanceid)
                if not _remove_instance_from_targetgroup(elb_client, tg_arn, instanceid):
                    logging.warning('Failed to remove instance from target group')
                else:
                    logging.info('      Successfully removed %s from Targetgroup - pausing for 60 seconds' % instanceid)
                # Pause for 60 seconds while connections drain on the instance
                time.sleep(60)
                logging.info('    Terminating instance %s' % instanceid)
                terminate_instance_id(configMap, **key_args)
                while(reachable==False):
                    checkinstancelist = list_instances(configMap, instance_name, **key_args)
                    print(len(checkinstancelist), len(growing_instance_list))
                    if len(checkinstancelist) > 0:
                        new_instance_id = list(set(checkinstancelist))
                        logging.info('Found newly launched instances: %s' % str(new_instance_id))

                        key_args['instance_id'] = new_instance_id[0]

                        instance_reachability = get_describe_instance_status(configMap, tg_arn, **key_args)
                        print(instance_reachability)
                        if instance_reachability == "passed":
                            reachable = True
                            growing_instance_list = checkinstancelist
                            #check load balancer
                            # logging.info('waiting 200 seconds for app to start...')
                            while not _is_instance_inService(elb_client, tg_arn, new_instance_id[0]):
                                logging.info('      Waiting for instance %s to be InService...' % new_instance_id[0])
                                time.sleep(45)
                    if not reachable:
                        logging.info('      waiting on valid status...')
                        time.sleep(45)
    pass


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


def get_target_group_arn(configMap, instance_name, client, **key_args):

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
