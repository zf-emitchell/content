import argparse
import demisto_client
import os
import ast
import json
import glob
import sys
import demisto_client
from demisto_client.demisto_api.rest import ApiException
from Tests.tools import update_server_configuration
from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS, run_threads_list, \
    run_command, get_yaml, str2bool, format_version, find_type
from Tests.configure_and_test_integration_instances import Build
from Tests.scripts.collect_tests_and_content_packs import get_list_of_files_in_the_pack

DOCKER_HARDENING_CONFIGURATION = {
    'docker.cpu.limit': '1.0',
    'docker.run.internal.asuser': 'true',
    'limit.docker.cpu': 'true',
    'python.pass.extra.keys': '--memory=1g##--memory-swap=-1##--pids-limit=256##--ulimit=nofile=1024:8192'
}
MARKET_PLACE_CONFIGURATION = {
    'content.pack.verify': 'false',
    'marketplace.initial.sync.delay': '0',
    'content.pack.ignore.missing.warnings.contentpack': 'true'
}


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server Master", "Demisto GA", "Demisto one before GA", "Demisto two before '
                                          'GA". The server url is determined by the AMI environment.')
    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--is-nightly', type=str2bool, help='Is nightly build')
    parser.add_argument('-pr', '--is_private', type=str2bool, help='Is private build')
    parser.add_argument('--packs', help='Pack path which was changed.')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)

    options = parser.parse_args()

    return options


def update_server_conf(build_options: Build):
    user_name = build_options.username
    password = build_options.password

    error_message = "Failed to update server configuration."
    server_configuration = DOCKER_HARDENING_CONFIGURATION
    server_configuration.update(MARKET_PLACE_CONFIGURATION)
    for server in build_options.servers:
        client = demisto_client.configure(server, verify_ssl=False, username=user_name, password=password)
        response_data, status_code = update_server_configuration(client=client,
                                                                 server_configuration=server_configuration,
                                                                 error_msg=error_message)
    return response_data, status_code


def configure_testing_integration():
    # TODO setup instance for integration.
    pass


def install_premium_packs(build: Build):
    server = build.servers[0]  # We are only testing on one server right now
    user_name = build.username
    password = build.password
    local_packs = glob.glob(
        "/home/runner/work/content-private/content-private/content/artifacts/packs/*.zip")
    with open('./Tests/content_packs_to_install.txt', 'r') as packs_stream:
        pack_ids = packs_stream.readlines()
        pack_ids_to_install = [pack_id.rstrip('\n') for pack_id in pack_ids]
    packs_install_msg = f'Installing the following packs: {pack_ids_to_install}'
    print(packs_install_msg)
    for local_pack in local_packs:
        if any(pack_id in local_pack for pack_id in pack_ids_to_install):
            """ Install packs from zip file.

                Args:
                    client (demisto_client): The configured client to use.
                    host (str): The server URL.
                    prints_manager (ParallelPrintsManager): Print manager object.
                    thread_index (int): the index (for prints_manager).
                    pack_path (str): path to pack zip.
                """
            header_params = {
                'Content-Type': 'multipart/form-data'
            }
            file_path = os.path.abspath(local_pack)
            files = {'file': file_path}

            message = 'Making "POST" request to server {} - to install all packs from file {}'.format(
                server, local_pack)
            print(message)

            client = demisto_client.configure(server, verify_ssl=False, username=user_name,
                                              password=password)
            try:
                response_data, status_code, _ = client.api_client.call_api(
                    resource_path='/contentpacks/installed/upload',
                    method='POST',
                    header_params=header_params, files=files)

                if 200 <= status_code < 300:
                    message = 'Pack from {} were successfully installed!\n'.format(local_pack)
                    print(message)
                else:
                    result_object = ast.literal_eval(response_data)
                    message = result_object.get('message', '')
                    err_msg = 'Failed to install packs - with status code {}\n{}\n'.format(
                        status_code, message)
                    raise Exception(err_msg)
            except Exception as e:
                if e.__class__ == ApiException:
                    err_msg = 'The request to install packs has failed. Reason:\n{}\n'.format(
                        str(e.body))
                    print(err_msg)
                else:
                    err_msg = 'The request to install packs has failed. Reason:\n{}\n'.format(
                        str(e))
                    print(err_msg)
                sys.exit(1)


def install_test_playbooks(playbooks_to_install, build):
    for playbook in playbooks_to_install:
        api_instance = demisto_client.configure(base_url=build.servers[0], username=build.username,
                                                password=build.password, debug=True)
        with open(playbook, 'r') as pb:
            response_data, status_code, _ = api_instance.import_playbook(file=pb)

    return response_data, status_code


def create_instance():
    #  TODO create an instance of the integration to test
    pass


def run_test_module():
    #  TODO Press the test button.
    pass


def run_test_playbooks():
    #  TODO Create incident and execute a test.
    pass


def format_test_results():
    #  TODO get test result object and print the results.
    pass


def get_list_of_playbooks_to_install_and_test(pack_paths):
    packs_to_install = {}
    pack_files = get_list_of_files_in_the_pack(pack_paths)
    for pack_file in pack_files:
        if 'TestPlaybooks' in pack_file:
            packs_to_install.update(pack_file)
    return packs_to_install


def process_results(response, status_code):
    continue_testing = True
    if status_code >= 300 or status_code < 200:
        continue_testing = False
        print(f"Step failed. Returned message is: {response}")
    return continue_testing


def install_license_to_server(build: Build):
    client = demisto_client.configure(build.servers[0], verify_ssl=False, username=build.username,
                                      password=build.password)
    license_path = '/home/runner/work/content-private/content-private/content-test-conf/demisto.lic'
    header_params = {
        'Content-Type': 'multipart/form-data'
    }
    file_path = os.path.abspath(license_path)
    files = {'file': file_path}

    message = 'Making "POST" request to server {} - to update the license {}'.format(
        build.servers[0], license_path)
    print(message)
    try:
        response_data, status_code, _ = client.api_client.call_api(
            resource_path='/license/upload',
            method='POST',
            header_params=header_params, files=files)
        if 200 <= status_code < 300:
            message = 'License was successfully updated!\n'
            print(message)
        else:
            result_object = ast.literal_eval(response_data)
            message = result_object.get('message', '')
            err_msg = f'Failed to install packs - with status code {status_code}\n{message}\n'
            raise Exception(err_msg)
    except ApiException:
        print("Failed to upload license.")
    return message, status_code


def main():
    options = options_handler()
    build_options = Build(options)
    pack_paths = options.packs
    playbooks_to_install = get_list_of_playbooks_to_install_and_test(pack_paths)
    continue_testing = True
    if continue_testing:
        response_data, status_code = update_server_conf(build_options)
        continue_testing = process_results(response_data, status_code)
    if continue_testing:
        response_data, status_code = install_license_to_server(build=build_options)
        continue_testing = process_results(response_data, status_code)
    if continue_testing:
        response_data, status_code = install_premium_packs(build=build_options)
        continue_testing = process_results(response_data, status_code)
    if continue_testing:
        response_data, status_code = install_test_playbooks(playbooks_to_install=playbooks_to_install,
                                                            build=build_options)


if __name__ == '__main__':
    main()
