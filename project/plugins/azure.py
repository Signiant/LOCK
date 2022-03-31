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


def rotate_autoscalers_cloud(configMap, username,  **key_args):

    auth = configMap['Global']['azure_credentials'][key_args.get('account')]
    credentials = ClientSecretCredential(auth.get('tenant'), auth.get('client_id'), auth.get('secret'))
    subscriptions = key_args.get('resource_group_subscriptionid')

    for item in subscriptions:
        to_rotate = []
        for key in item:
            region = key
            for resource_group in item.get(region):
                resource_group_name = resource_group
                sub_id = item.get(region).get(resource_group)
                client = ResourceManagementClient(credentials, sub_id)
                compute_client = ComputeManagementClient(credentials, sub_id)
                resource_groups = client.resources.list_by_resource_group(resource_group_name)
                for rg in resource_groups:
                    if rg.type == 'Microsoft.Compute/virtualMachines':
                        try:
                            result = compute_client.virtual_machines.get(resource_group_name,
                                                                         rg.name,
                                                                         expand='instanceView')
                            if 'running' in result.instance_view.statuses[1].display_status:
                                to_rotate.append(rg.name)
                            else:
                                logging.warning(f'{rg.name} Not in RUNNING state - skipping')
                        except msrestazure.azure_exceptions.CloudError as e:
                            if 'not found' in e.message:
                                logging.warning(f'{rg.name} Not Found - skipping')

        logging.info(f'Found the following VMs: {to_rotate}')
        # Build dns names
        for vm in to_rotate:  # rotate key for server type
            markers = []
            commands = []
            if 'autoscaler' in vm:
                for host in key_args.get('autoscalers'):
                    r = region.replace('-', '')
                    if r in host:
                        key_args['hostname']=host
                logging.info('      Writing key to '+key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-','') in pkey:
                        key_args['pkey'] = pkey

                for marker in key_args.get('autoscaler_markers_commands'):
                    markers.append(marker)
                    commands.append(key_args.get('autoscaler_markers_commands').get(marker))
                key_args['commands'] = commands
                key_args['markers'] = markers
                ssh_server_command(configMap, username, **key_args)
            else:  # its a flight server
                key_args['hostname'] = key_args.get('f_host').replace('<SERVER>', vm).replace('<REGION>', region.replace('-', ''))
                logging.info('      Writing key to '+key_args['hostname'])
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
        logging.info('Dry run ')
    else:
        client.set_secret(key_args.get('key_name'), values.access_key[0], logging_enable=False)
        client.set_secret(key_args.get('key_secret'), values.access_key[1], logging_enable=False)
        logging.info("      Access key and Secret key written to key vault")
        pass


def update_pipeline_service_connection(configMap, username,  **key_args):
    personal_access_token = configMap['Global']['azure_credentials']['personal_access_token']
    organization_url = key_args.get('devops_organization_url')
    projects = key_args.get('projects')

    # Create a connection to the org
    credentials = BasicAuthentication('', personal_access_token)
    connection = Connection(base_url=organization_url, creds=credentials)
    # Get a service endpoint client
    service_endpoint_client = connection.clients_v6_0.get_service_endpoint_client()

    for project in projects:
        for endpoint in projects[project]:
            service_endpoints_details = service_endpoint_client.get_service_endpoint_details(project=project,
                                                                                             endpoint_id=endpoint)

            if service_endpoints_details:
                logging.info(f'Retrieved endpoint details for {service_endpoints_details.name}')
                new_service_endpoint = service_endpoints_details
                if values.DryRun is True:
                    logging.info('Dry run ')
                else:
                    # Update the ACCESS Key and Secret
                    new_service_endpoint.authorization.parameters['username'] = values.access_key[0]
                    new_service_endpoint.authorization.parameters['password'] = values.access_key[1]
                    # Now update the service endpoint
                    logging.info(f'Attempting to update credentials for {new_service_endpoint.name}')
                    service_endpoint_client.update_service_endpoint(new_service_endpoint, endpoint)
                    logging.info(f"      Service Connection {new_service_endpoint.name} Updated")
