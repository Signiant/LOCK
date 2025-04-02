import logging
import msrestazure.azure_exceptions
from azure.mgmt.compute import ComputeManagementClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.resource import ResourceManagementClient
from azure.identity import ClientSecretCredential
from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from project.plugins.ssh import ssh_server_command
from project import values

logging.getLogger('azure.keyvault.secrets').setLevel(logging.CRITICAL)
logging.getLogger('azure.mgmt.resource.resources').setLevel(logging.CRITICAL)
logging.getLogger('azure.identity').setLevel(logging.CRITICAL)
logging.getLogger('azure.common.credentials').setLevel(logging.CRITICAL)
logging.getLogger('azure.mgmt.compute').setLevel(logging.CRITICAL)
logging.getLogger('azure.core').setLevel(logging.CRITICAL)
logging.getLogger('azure').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)


def rotate_vms(configMap, username,  **key_args):
    auth = configMap['Global']['azure_credentials'][key_args.get('account')]
    credentials = ClientSecretCredential(auth.get('tenant'), auth.get('client_id'), auth.get('secret'))
    subscriptions = key_args.get('resource_group_subscriptionid')

    for subscription in subscriptions:
        to_rotate = []
        for region in subscription:
            for resource_group_name_prefix, subscription_id in subscription.get(region).items():
                resource_client = ResourceManagementClient(credentials, subscription_id, logging_enable=False)
                compute_client = ComputeManagementClient(credentials, subscription_id)
                
                resource_groups = resource_client.resource_groups.list()
                matching_resource_groups = [
                    rg for rg in resource_groups if rg.name.startswith(resource_group_name_prefix)
                ]
                for matching_resource_group in matching_resource_groups:
                    resource_group_name = matching_resource_group.name
                    resources = resource_client.resources.list_by_resource_group(resource_group_name)
                    for resource in resources:
                        if resource.type == 'Microsoft.Compute/virtualMachines':
                            try:
                                result = compute_client.virtual_machines.get(resource_group_name,
                                                                            resource.name,
                                                                            expand='instanceView')
                                if len (result.instance_view.statuses) > 1 and 'running' in result.instance_view.statuses[1].display_status and result.instance_view.computer_name:
                                    to_rotate.append(result.instance_view.computer_name)
                                else:
                                    logging.warning(f'User {username}: {resource.name} Not in RUNNING state - skipping')
                            except msrestazure.azure_exceptions.CloudError as e:
                                if 'not found' in e.message:
                                    logging.warning(f'User {username}: {resource.name} Not Found - skipping')

        logging.info(f'User {username}: Found the following VMs: {to_rotate}')
        # Build dns names
        for vm in to_rotate:
            markers = []
            commands = []
            key_args['hostname'] = key_args.get('f_host').replace('<SERVER>', vm)
            logging.info(f'User {username}: Writing key to '+key_args['hostname'])
            for pkey in key_args.get('pkeys'):
                if region.replace('-', '') in pkey:
                    key_args['pkey'] = pkey
            for marker in key_args.get('fadmin_markers_commands'):
                markers.append(marker)
                commands.append(key_args.get('fadmin_markers_commands').get(marker))
            key_args['commands'] = commands
            key_args['markers'] = markers
            ssh_server_command(configMap, username, **key_args)


def set_key_vault(configMap, username,  **key_args):

    key_vault_uri = key_args.get('vault_uri')
    auth = configMap['Global']['azure_credentials'][key_args.get('account')]

    credential = ClientSecretCredential(auth.get('tenant'),
                                        auth.get('client_id'),
                                        auth.get('secret'))

    client = SecretClient(vault_url=key_vault_uri, credential=credential, logging_enable=False)

    if values.DryRun is True:
        logging.info(f'User {username}: Dry run ')
    else:
        client.set_secret(key_args.get('key_name'), values.access_key[0], logging_enable=False)
        client.set_secret(key_args.get('key_secret'), values.access_key[1], logging_enable=False)
        logging.info(f"User {username}: Access key and Secret key written to key vault")
        pass


def update_pipeline_service_connection(configMap, username,  **key_args):
    personal_access_token = configMap['Global']['azure_credentials']['personal_access_token']
    organization_url = key_args.get('devops_organization_url')
    projects = key_args.get('projects')

    # Create a connection to the org
    credentials = BasicAuthentication('', personal_access_token)
    connection = Connection(base_url=organization_url, creds=credentials)
    # Get a service endpoint client
    service_endpoint_client = connection.clients.get_service_endpoint_client()

    for project in projects:
        for endpoint in projects[project]:
            service_endpoints_details = service_endpoint_client.get_service_endpoint_details(project=project,
                                                                                             endpoint_id=endpoint)

            if service_endpoints_details:
                logging.info(f'User {username}: Retrieved endpoint details for {service_endpoints_details.name}')
                new_service_endpoint = service_endpoints_details
                if values.DryRun is True:
                    logging.info(f'User {username}: Dry run ')
                else:
                    # Update the ACCESS Key and Secret
                    new_service_endpoint.authorization.parameters['username'] = values.access_key[0]
                    new_service_endpoint.authorization.parameters['password'] = values.access_key[1]
                    # Now update the service endpoint
                    logging.info(f'User {username}: Attempting to update credentials for {new_service_endpoint.name}')
                    service_endpoint_client.update_service_endpoint(new_service_endpoint, endpoint)
                    logging.info(f"User {username}: Service Connection {new_service_endpoint.name} Updated")
