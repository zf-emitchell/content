import copy
import json
import os

import demisto_sdk.commands.common.tools as demisto_sdk_tools
from ruamel.yaml import YAML

from Tests.scripts.collect_tests_and_content_packs import (
    RANDOM_TESTS_NUM, TestConf, create_filter_envs_file, get_modified_files_for_testing,
    get_test_list_and_content_packs_to_install, collect_content_packs_to_install,
    get_from_version_and_to_version_bounderies)

with open('Tests/scripts/infrastructure_tests/tests_data/mock_id_set.json', 'r') as mock_id_set_f:
    MOCK_ID_SET = json.load(mock_id_set_f)
with open('Tests/scripts/infrastructure_tests/tests_data/mock_conf.json', 'r') as mock_conf_f:
    MOCK_CONF = json.load(mock_conf_f)


class TestUtils(object):
    __test__ = False

    class PackIgnoreManager:
        def __init__(self, test_file_name=None):
            self.test_file_name = test_file_name
            self.pack_ignore_path = os.path.join('Tests/scripts/infrastructure_tests/tests_data/fake_pack/.pack-ignore')
            with open(self.pack_ignore_path, 'r') as f:
                self.previous_pack_ignore_contents = f.read()

        def __enter__(self):
            if self.test_file_name:
                with open(self.pack_ignore_path, 'w') as f:
                    f.write(f'[file:{self.test_file_name}]\nignore=auto-test')

        def __exit__(self, exc_type, exc_val, exc_tb):
            with open(self.pack_ignore_path, 'w') as f:
                f.write(self.previous_pack_ignore_contents)

    @staticmethod
    def save_yaml(path, data):
        ryaml = YAML()
        ryaml.allow_duplicate_keys = True

        with open(path, 'w') as f:
            ryaml.dump(data, f)

    @staticmethod
    def create_integration(name, with_commands=None, pack=""):
        mock_integration = demisto_sdk_tools.get_yaml(
            'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/fake_integration.yml')

        mock_integration['commonfields']['id'] = name
        mock_integration['name'] = name
        mock_integration['display'] = name

        save_path = os.path.join('Tests/scripts/infrastructure_tests/tests_data/mock_integrations', name + '.yml')
        TestUtils.save_yaml(save_path, mock_integration)

        commands = [
            "fake-command"
        ]

        if with_commands:
            commands = with_commands

        integration = {
            'path': save_path,
            'id_set': {
                name: {
                    "name": name,
                    "fromversion": "4.1.0",
                    "toversion": "5.4.9",
                    "file_path": save_path,
                    "commands": commands,
                    "pack": pack
                }
            }
        }

        return integration

    @staticmethod
    def create_script(name):
        mock_script = demisto_sdk_tools.get_yaml(
            'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/fake-script.yml')

        mock_script['commonfields']['id'] = name
        mock_script['name'] = name

        save_path = os.path.join('Tests/scripts/infrastructure_tests/tests_data/mock_scripts', name + '.yml')
        TestUtils.save_yaml(save_path, mock_script)

        script = {
            'path': save_path,
            'id_set': {
                name: {
                    "name": name,
                    "fromversion": "4.1.0",
                    "toversion": "5.4.9",
                    "file_path": save_path,
                }
            }
        }

        return script

    @staticmethod
    def create_test_playbook(name, with_scripts=None, with_integration_commands=None):
        test_playbook_default = demisto_sdk_tools.get_yaml(
            'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml')

        test_playbook_default['id'] = name
        test_playbook_default['name'] = name

        file_path = os.path.join('Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks', name + '.yml')
        TestUtils.save_yaml(file_path, test_playbook_default)

        playbook_id_set = {
            name: {
                "name": name,
                "file_path": file_path
            }
        }
        if with_scripts:
            playbook_id_set[name]['implementing_scripts'] = with_scripts

        if with_integration_commands:
            playbook_id_set[name]['command_to_integration'] = with_integration_commands

        test_playbook = {
            'path': file_path,
            'id_set': playbook_id_set
        }
        return test_playbook

    @staticmethod
    def mock_get_modified_files(mocker, modified_files_list, is_conf_json=False):
        return mocker.patch('Tests.scripts.collect_tests_and_content_packs.get_modified_files_for_testing',
                            return_value=create_get_modified_files_ret(
                                modified_files_list=modified_files_list,
                                is_conf_json=is_conf_json
                            ))

    @staticmethod
    def mock_get_test_list_and_content_packs_to_install(mocker):
        return mocker.patch('Tests.scripts.collect_tests_and_content_packs.get_test_list_and_content_packs_to_install',
                            return_value='Detonate URL - Generic Test')

    @staticmethod
    def mock_run_command(mocker, on_command, return_value):
        def on_run_command(*args):
            command = args[0]
            if command == on_command:
                return return_value

            return ''

        mock = mocker.patch('demisto_sdk.commands.common.tools.run_command')
        mock.side_effect = on_run_command
        return mock

    @staticmethod
    def create_tests_conf(with_test_configuration=None):
        with open('Tests/scripts/infrastructure_tests/tests_data/mock_conf.json', 'r') as mock_conf_f:
            conf = json.load(mock_conf_f)

        if with_test_configuration:
            conf['tests'].append(with_test_configuration)

        return TestConf(conf)

    @staticmethod
    def create_id_set(with_integration=None, with_test_playbook=None, with_scripts=None):
        with open('Tests/scripts/infrastructure_tests/tests_data/mock_id_set.json', 'r') as mock_id_set_f:
            id_set = json.load(mock_id_set_f)

        if with_integration:
            id_set['integrations'].append(with_integration)

        if with_test_playbook:
            id_set['TestPlaybooks'].append(with_test_playbook)

        if with_scripts:
            id_set['scripts'].append(with_scripts)

        return id_set

    @staticmethod
    def delete_files(files):
        for f in files:
            if isinstance(f, dict) and 'path' in f:
                file_path = f['path']
            else:
                file_path = f

            if os.path.exists(file_path):
                os.remove(file_path)


class TestChangedPlaybook:
    TEST_ID = 'Calculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/CommonPlaybooks/Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}
        assert content_packs == {"Base", "DeveloperTools", "CommonPlaybooks", "FakePack"}


class TestChangedTestPlaybook:
    TEST_ID = 'EWSv2_empty_attachment_test'
    # points at a real file. if that file will change path the test should fail
    GIT_DIFF_RET = "M Packs/EWS/TestPlaybooks/playbook-EWSv2_empty_attachment_test.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}
        assert content_packs == {"Base", "DeveloperTools", "EWS"}

    def test_changed_runnable_test__mocked_get_modified_files(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in playbook file
        test_id = 'fake_test_playbook'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.1.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools", 'fake_pack'}

    def test_create_filter_envs_file_with_default_versions(self):
        """
        Given:
            - from_version is 0.0.0
            - to_version is 99.99.99
        When:
            - running create_filter_envs_file
        Then:
            - Create filter_envs.json file with all as true
        """
        create_filter_envs_file('0.0.0', '99.99.99')
        with open("./Tests/filter_envs.json", "r") as filter_envs_file:
            filter_envs = json.load(filter_envs_file)
        assert filter_envs.get('Demisto PreGA') is True
        assert filter_envs.get('Demisto Marketplace') is True
        assert filter_envs.get('Demisto 6.0') is True
        assert filter_envs.get('Demisto one before GA') is True
        assert filter_envs.get('Demisto GA') is True

    def test_get_from_version_and_to_version_from_modified_files(self):
        """
        Given:
            - fake_test_playbook is fromversion 4.1.0 in integration file
            - two_before_ga is '4.0.0'
            - one_before_ga is '4.0.1'
            - ga is '4.1.0'
        When:
            - running get_test_list_and_content_packs_to_install
            - running create_filter_envs_file
        Then:
            - Create test list with fake_test_playbook
            - Create filter_envs.json file with Demisto two before GA False and Demisto one before GA False

        """
        two_before_ga = '4.0.0'
        one_before_ga = '4.0.1'
        ga = '4.1.0'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/fake_test_playbook.yml'
        modified_files_list, modified_tests_list, changed_common, _, sample_tests, modified_metadata_list, _, _ = \
            create_get_modified_files_ret(modified_files_list=[test_path], modified_tests_list=[test_path])

        all_modified_files_paths = set(modified_files_list + modified_tests_list + changed_common + sample_tests)
        from_version, to_version = get_from_version_and_to_version_bounderies(all_modified_files_paths,
                                                                              MOCK_ID_SET)

        create_filter_envs_file(from_version, to_version, two_before_ga, one_before_ga, ga)
        with open("./Tests/filter_envs.json", "r") as filter_envs_file:
            filter_envs = json.load(filter_envs_file)
        assert filter_envs.get('Demisto PreGA') is True
        assert filter_envs.get('Demisto Marketplace') is True
        assert filter_envs.get('Demisto 6.0') is True
        assert filter_envs.get('Demisto one before GA') is False
        assert filter_envs.get('Demisto GA') is False

    def test_get_from_and_to_version_from_modified_files(self):
        """
        Given:
            - Integration path with fromversion 6.0.
            - Playbook path with toversion 5.9.9
            - test playbook path with fromversion 5.0.
        When:
            - running get_test_list_and_content_packs_to_install
        Then:
            - Check that the toversion is the default (99.99.99)
            - Check minimum version is 5.0.0

        """
        test_integration_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/' \
                                'test_fake_integration.yml'
        test_playbook_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/' \
                             'playbook-fake_test_playbook_to_version.yml'
        playbook_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_playbooks/test_fake_playbook.yml'

        modified_files_list = [test_integration_path, playbook_path]
        modified_tests_list = [test_playbook_path]
        all_modified_files_paths = set(modified_files_list + modified_tests_list)
        from_version, to_version = get_from_version_and_to_version_bounderies(all_modified_files_paths,
                                                                              MOCK_ID_SET)

        assert '5.0.0' in from_version
        assert '99.99.99' in to_version

    def test_changed_unrunnable_test__playbook_fromvesion_2(self, mocker):
        # future_playbook_1 is fromversion 99.99.99 in conf file
        test_id = 'future_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}

    def test_changed_runnable_test__playbook_fromversion(self, mocker):
        # future_playbook_1 is toversion 99.99.99 in conf file
        test_id = 'future_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/future_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('99.99.99', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}

    def test_changed_unrunnable_test__skipped_test(self, mocker):
        test_id = 'skipped_integration_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/skipped_integration_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}

    def test_changed_unrunnable_test__skipped_integration(self, mocker):
        test_id = 'skipped_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/skipped_test_playbook_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[test_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}


class TestChangedIntegration:
    TEST_ID = 'PagerDuty Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/PagerDuty/Integrations/PagerDuty/PagerDuty.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}
        assert content_packs == {"Base", "DeveloperTools", "PagerDuty"}

    def test_changed_unrunnable_test__integration_toversion(self, mocker):
        test_id = 'past_test_playbook_1'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/past_test_playbook_1.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_integrations/past_integration_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}


class TestChangedIntegrationAndPlaybook:
    TEST_ID = 'PagerDuty Test\nCalculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/PagerDuty/Integrations/PagerDuty/PagerDuty.py\n" \
                   "M Packs/CommonPlaybooks/Playbooks/playbook-Calculate_Severity_By_Highest_DBotScore.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == set(self.TEST_ID.split('\n'))
        assert content_packs == {"Base", "DeveloperTools", 'CommonPlaybooks', 'PagerDuty', 'FakePack'}


class TestChangedScript:
    TEST_ID = 'Extract Indicators From File - test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/CommonScripts/Scripts/ExtractIndicatorsFromTextFile/ExtractIndicatorsFromTextFile.yml"

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert filterd_tests == {self.TEST_ID}
        assert content_packs == {"Base", "DeveloperTools", "CommonScripts"}

    def test_changed_unrunnable_test__integration_toversion(self, mocker):
        test_id = 'past_test_playbook_2'
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/past_test_playbook_2.yml'
        file_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_scripts/past_script_1.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_files_list=[file_path],
                                                               modified_tests_list=[test_path])
        filterd_tests, content_packs = get_mock_test_list('4.0.0', get_modified_files_ret, mocker)

        assert test_id in filterd_tests
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}


class TestSampleTesting:
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Tests/scripts/integration-test.yml"

    def test_sample_tests(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)

        assert len(filterd_tests) >= RANDOM_TESTS_NUM
        assert "Base" in content_packs
        assert "DeveloperTools" in content_packs

    def test_sample_tests__with_test(self, mocker):
        """
        Given:
            - Sample tests is non empty
            - Modified test equals 1 test
        When:
            - Calling get_modified_files
        Then:
            - Test filter should return 1 test
        """
        test_path = 'Tests/scripts/infrastructure_tests/tests_data/mock_test_playbooks/past_test_playbook_2.yml'
        get_modified_files_ret = create_get_modified_files_ret(modified_tests_list=[test_path],
                                                               sample_tests=['test'])
        filterd_tests, content_packs = get_mock_test_list(mocker=mocker, git_diff_ret=self.GIT_DIFF_RET,
                                                          get_modified_files_ret=get_modified_files_ret)
        assert len(filterd_tests) == 1
        assert content_packs == {"Base", "DeveloperTools"}


class TestChangedCommonTesting:
    TEST_ID = 'TestCommonPython'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = "M Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml"

    def test_all_tests(self):
        filterd_tests, content_packs = get_mock_test_list(git_diff_ret=self.GIT_DIFF_RET)
        assert len(filterd_tests) >= RANDOM_TESTS_NUM
        assert content_packs == {"DeveloperTools", 'Base', 'HelloWorld'}


class TestPackageFilesModified:
    TEST_ID = 'PagerDuty Test\nCalculate Severity - Standard - Test'
    # points at a real file. if that file changes path the test should fail
    GIT_DIFF_RET = """M Packs/Active_Directory_Query/Integrations/Active_Directory_Query/Active_Directory_Query.py
A       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/cert.pem
M       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/connection_test.py
A       Packs/Active_Directory_Query/Integrations/Active_Directory_Query/key.pem
"""

    def test_changed_runnable_test__unmocked_get_modified_files(self):
        files_list, tests_list, all_tests, is_conf_json, sample_tests, modified_metadata_list, is_reputations_json, \
            is_indicator_json = get_modified_files_for_testing(self.GIT_DIFF_RET)
        assert len(sample_tests) == 0
        assert 'Packs/Active_Directory_Query/Integrations/' \
               'Active_Directory_Query/Active_Directory_Query.yml' in files_list


class TestNoChange:
    def test_no_change(self, mocker):
        # fake_test_playbook is fromversion 4.1.0 in playbook file
        get_modified_files_ret = create_get_modified_files_ret()
        filterd_tests, content_packs = get_mock_test_list('4.1.0', get_modified_files_ret, mocker)

        assert len(filterd_tests) >= RANDOM_TESTS_NUM
        assert content_packs == {"Base", "DeveloperTools", "HelloWorld"}


def create_get_modified_files_ret(modified_files_list=None, modified_tests_list=None, changed_common=None,
                                  is_conf_json=False, sample_tests=None, modified_metadata_list=None,
                                  is_reputations_json=None, is_indicator_json=None):
    """
    Returns return value for get_modified_files() to be used with a mocker patch
    """
    return (
        modified_files_list if modified_files_list is not None else [],
        modified_tests_list if modified_tests_list is not None else [],
        changed_common if changed_common is not None else [],
        is_conf_json,
        sample_tests if sample_tests is not None else [],
        modified_metadata_list if modified_metadata_list is not None else [],
        is_reputations_json if is_reputations_json is not None else [],
        is_indicator_json if is_indicator_json is not None else []
    )


TWO_BEFORE_GA_VERSION = '4.5.0'


def get_mock_test_list(minimum_server_version=TWO_BEFORE_GA_VERSION, get_modified_files_ret=None, mocker=None,
                       git_diff_ret=''):
    branch_name = 'BranchA'
    if get_modified_files_ret is not None:
        mocker.patch(
            'Tests.scripts.collect_tests_and_content_packs.get_modified_files_for_testing',
            return_value=get_modified_files_ret
        )
    tests, content_packs = get_test_list_and_content_packs_to_install(
        git_diff_ret, branch_name, minimum_server_version, id_set=MOCK_ID_SET, conf=TestConf(MOCK_CONF)
    )
    return tests, content_packs


def test_skipped_integration_should_not_be_tested(mocker):
    """
    Given
    - conf.json file with IntegrationA is skipped
    - no tests provided for IntegrationA

    When
    - filtering tests to run

    Then
    - ensure IntegrationA is skipped
    - ensure the validation not failing
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    # Given
    # - conf.json file with IntegrationA is skipped
    # - no tests provided for IntegrationA
    fake_integration = TestUtils.create_integration(name='integration_a', with_commands=['a-command'])

    # mark as modified
    TestUtils.mock_get_modified_files(mocker,
                                      modified_files_list=[
                                          fake_integration['path']
                                      ])

    mock_conf_dict = copy.deepcopy(MOCK_CONF)
    mock_conf_dict['skipped_integrations']['integration_a'] = 'comment'

    fake_id_set = TestUtils.create_id_set()

    # When
    # - filtering tests to run
    filtered_tests = get_test_list_and_content_packs_to_install(
        files_string='',
        branch_name='dummy_branch',
        minimum_server_version=TWO_BEFORE_GA_VERSION,
        conf=TestConf(mock_conf_dict),
        id_set=fake_id_set
    )

    # Then
    # - ensure IntegrationA is skipped
    assert 'integration_a' not in filtered_tests

    # - ensure the validation not failing
    assert not collect_tests_and_content_packs._FAILED


def test_integration_has_no_test_playbook_should_fail_on_validation(mocker):
    """
    Given
    - integration_a was modified
    - no tests provided for integration_a

    When
    - filtering tests to run

    Then
    - ensure the validation is failing
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    try:
        # Given
        # - integration_a was modified
        # - no tests provided for integration_a
        fake_integration = TestUtils.create_integration(name='integration_a', with_commands=['a-command'])

        # mark as modified
        TestUtils.mock_get_modified_files(mocker,
                                          modified_files_list=[
                                              fake_integration['path']
                                          ])

        # - both in conf.json
        fake_conf = TestUtils.create_tests_conf()

        fake_id_set = TestUtils.create_id_set(
            with_integration=fake_integration['id_set']
        )

        # When
        # - filtering tests to run
        get_test_list_and_content_packs_to_install(
            files_string='',
            branch_name='dummy_branch',
            minimum_server_version=TWO_BEFORE_GA_VERSION,
            conf=fake_conf,
            id_set=fake_id_set
        )

        # Then
        # - ensure the validation is failing
        assert collect_tests_and_content_packs._FAILED
    finally:
        # delete the mocked files
        TestUtils.delete_files([
            fake_integration['path']
        ])

        # reset _FAILED flag
        collect_tests_and_content_packs._FAILED = False


def test_conf_has_modified(mocker):
    """
    Given
    - Tests/conf.json has been modified

    When
    - filtering tests to run

    Then
    - ensure the validation not failing
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    try:
        # Given
        # - Tests/conf.json has been modified
        TestUtils.mock_get_modified_files(mocker,
                                          modified_files_list=[],
                                          is_conf_json=True)

        TestUtils.mock_run_command(
            mocker,
            on_command='git diff origin/master...dummy_branch Tests/conf.json',
            return_value='something'
        )
        # - both in conf.json
        fake_conf = TestUtils.create_tests_conf()

        fake_id_set = TestUtils.create_id_set()

        # When
        # - filtering tests to run

        get_test_list_and_content_packs_to_install(
            files_string='',
            branch_name='dummy_branch',
            minimum_server_version=TWO_BEFORE_GA_VERSION,
            conf=fake_conf,
            id_set=fake_id_set
        )

        # Then
        # - ensure the validation not failing
        assert not collect_tests_and_content_packs._FAILED
    finally:
        # reset _FAILED flag
        collect_tests_and_content_packs._FAILED = False


def test_dont_fail_integration_on_no_tests_if_it_has_test_playbook_in_conf(mocker):
    """
    If there is an integration in conf.json configured with test playbook
    Ensure that this integration don't fails on validation.

    Given
    - integration_a that fetches incidents
    - test_playbook_a exists that should test FetchFromInstance of integration_a
    - both in conf.json

    When
    - filtering tests to run

    Then
    - ensure test_playbook_a will run/returned
    - ensure the validation not failing
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    # Given
    # - integration_a exists
    fake_integration = TestUtils.create_integration(name='integration_a', with_commands=['a-command'])

    # mark as modified
    TestUtils.mock_get_modified_files(mocker,
                                      modified_files_list=[
                                          fake_integration['path']
                                      ])

    # - test_playbook_a exists that should test FetchFromInstance of integration_a
    fake_test_playbook = TestUtils.create_test_playbook(name='test_playbook_a',
                                                        with_scripts=['FetchFromInstance'])

    try:
        # - both in conf.json
        fake_conf = TestUtils.create_tests_conf(
            with_test_configuration={
                'integrations': 'integration_a',
                'playbookID': 'test_playbook_a'
            }
        )

        fake_id_set = TestUtils.create_id_set(
            with_integration=fake_integration['id_set'],
            with_test_playbook=fake_test_playbook['id_set']
        )

        # When
        # - filtering tests to run
        filtered_tests, content_packs = get_test_list_and_content_packs_to_install(
            files_string='',
            branch_name='dummy_branch',
            minimum_server_version=TWO_BEFORE_GA_VERSION,
            conf=fake_conf,
            id_set=fake_id_set
        )

        # Then
        # - ensure test_playbook_a will run/returned
        assert 'test_playbook_a' in filtered_tests

        # - ensure the validation not failing
        assert not collect_tests_and_content_packs._FAILED
    finally:
        # delete the mocked files
        TestUtils.delete_files([
            fake_integration['path'],
            fake_test_playbook['path']
        ])

        # reset _FAILED flag
        collect_tests_and_content_packs._FAILED = False


class TestExtractMatchingObjectFromIdSet:
    def test_mismatching_script_id(self, mocker):
        """
        Given
        - integration_a was modified
        - tests were provided for integration_a with mismatching id

        When
        - filtering tests to run

        Then
        - ensure test_playbook_a will run/returned
        """
        from Tests.scripts import collect_tests_and_content_packs
        collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

        # Given
        # - integration_a exists
        script_name = 'script_a'
        fake_script = TestUtils.create_script(name=script_name)

        # - tests were provided for integration_a with mismatching id
        id_set_obj = fake_script['id_set'][script_name]
        fake_script['id_set'] = {'wrong_id': id_set_obj}

        # mark as modified
        TestUtils.mock_get_modified_files(mocker,
                                          modified_files_list=[
                                              fake_script['path']
                                          ])

        # - test_playbook_a exists that should test script_a
        fake_test_playbook = TestUtils.create_test_playbook(name='test_playbook_a',
                                                            with_scripts=[script_name])

        try:
            # - both in conf.json
            fake_conf = TestUtils.create_tests_conf(
                with_test_configuration={
                    'playbookID': 'test_playbook_a'
                }
            )

            fake_id_set = TestUtils.create_id_set(
                with_scripts=fake_script['id_set'],
                with_test_playbook=fake_test_playbook['id_set']
            )

            # When
            # - filtering tests to run
            filtered_tests, content_packs = get_test_list_and_content_packs_to_install(
                files_string='',
                branch_name='dummy_branch',
                minimum_server_version=TWO_BEFORE_GA_VERSION,
                conf=fake_conf,
                id_set=fake_id_set
            )

            # Then
            # - ensure test_playbook_a will run/returned
            assert 'test_playbook_a' in filtered_tests
            assert content_packs == {"Base", "DeveloperTools"}

            # - ensure the validation not failing
            assert not collect_tests_and_content_packs._FAILED
        finally:
            # delete the mocked files
            TestUtils.delete_files([
                fake_script['path'],
                fake_test_playbook['path']
            ])

            # reset _FAILED flag
            collect_tests_and_content_packs._FAILED = False


def test_modified_integration_content_pack_is_collected(mocker):
    """
    Given
    - Modified integration named GreatIntegration which is in pack named GreatPack.

    When
    - Collecting content packs to install.

    Then
    - Ensure the content pack GreatPack is collected.
    - Ensure the collection runs successfully.
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    pack_name = "GreatPack"
    integration_name = "GreatIntegration"
    test_name = "GreatTest"
    fake_integration = TestUtils.create_integration(
        name=integration_name, with_commands=["great-command"], pack=pack_name
    )
    fake_test_playbook = TestUtils.create_test_playbook(name=test_name, with_scripts=["FetchFromInstance"])

    try:
        TestUtils.mock_get_modified_files(mocker, modified_files_list=[fake_integration['path']])
        fake_id_set = TestUtils.create_id_set(
            with_integration=fake_integration["id_set"],
            with_test_playbook=fake_test_playbook["id_set"]
        )

        fake_conf = TestUtils.create_tests_conf(
            with_test_configuration={
                "integrations": integration_name,
                "playbookID": test_name
            }
        )

        filtered_tests, content_packs = get_test_list_and_content_packs_to_install(
            files_string="",
            branch_name="dummy-branch",
            minimum_server_version=TWO_BEFORE_GA_VERSION,
            conf=fake_conf,
            id_set=fake_id_set
        )

        assert content_packs == {"Base", "DeveloperTools", pack_name}
        assert filtered_tests == {test_name}
        assert not collect_tests_and_content_packs._FAILED
    finally:
        TestUtils.delete_files([
            fake_integration["path"],
            fake_test_playbook["path"]
        ])

        collect_tests_and_content_packs._FAILED = False


def test_pack_ignore_test_is_skipped(mocker):
    """
    Given
    - Modified integration named GreatIntegration which is in pack named GreatPack.
    - Test playbook that is skipped in .pack-ignore

    When
    - Collecting content packs to install and tests.

    Then
    - Ensure test playbook is not collected
    - Ensure the content pack GreatPack is collected.
    - Ensure the collection runs successfully.
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    pack_name = "GreatPack"
    integration_name = "GreatIntegration"
    test_name = "GreatTest"
    fake_integration = TestUtils.create_integration(
        name=integration_name, with_commands=["great-command"], pack=pack_name
    )
    fake_test_playbook = TestUtils.create_test_playbook(name=test_name, with_scripts=["FetchFromInstance"])

    pack_ignore_mgr = TestUtils.PackIgnoreManager(os.path.basename(fake_test_playbook['path']))

    try:
        mocker.patch.object(os.path, 'join', return_value=fake_test_playbook['path'])
        mocker.patch.object(demisto_sdk_tools, 'get_pack_ignore_file_path', return_value=pack_ignore_mgr.pack_ignore_path)
        TestUtils.mock_get_modified_files(mocker, modified_files_list=[fake_integration['path']])
        fake_id_set = TestUtils.create_id_set(
            with_integration=fake_integration["id_set"],
            with_test_playbook=fake_test_playbook["id_set"]
        )

        fake_conf = TestUtils.create_tests_conf(
            with_test_configuration={
                "integrations": integration_name,
                "playbookID": test_name
            }
        )

        # add test playbook to ignore list and clean afterward
        with pack_ignore_mgr:
            filtered_tests, content_packs = get_test_list_and_content_packs_to_install(
                files_string="",
                branch_name="dummy-branch",
                minimum_server_version=TWO_BEFORE_GA_VERSION,
                conf=fake_conf,
                id_set=fake_id_set
            )

            assert content_packs == {"Base", "DeveloperTools", pack_name}
            assert not filtered_tests
            assert not collect_tests_and_content_packs._FAILED
    finally:
        TestUtils.delete_files([
            fake_integration["path"],
            fake_test_playbook["path"]
        ])

        collect_tests_and_content_packs._FAILED = False


def test_collect_content_packs_to_install(mocker):
    """
    Given
    - ID set of content entities
    - Set of integration IDs which contain integration named GreatIntegration which is in pack named GreatPack.
    - Set of script names which contain script named fake-script which is in pack named FakePack.
    - Set of playbook names which contain playbook named fake-playbook which is in pack named FakePack.

    When
    - Collecting content packs to install - running `collect_content_packs_to_install()`.

    Then
    - Ensure the content packs GreatPack and FakePack are collected.
    - Ensure the collection runs successfully.
    """
    from Tests.scripts import collect_tests_and_content_packs
    collect_tests_and_content_packs._FAILED = False  # reset the FAILED flag

    great_pack_name = "GreatPack"
    great_integration_name = "GreatIntegration"
    great_test_name = "GreatTest"
    fake_integration = TestUtils.create_integration(
        name=great_integration_name, with_commands=["great-command"], pack=great_pack_name
    )
    fake_test_playbook = TestUtils.create_test_playbook(name=great_test_name, with_scripts=["FetchFromInstance"])

    try:
        TestUtils.mock_get_modified_files(mocker, modified_files_list=[fake_integration['path']])
        fake_id_set = TestUtils.create_id_set(
            with_integration=fake_integration["id_set"],
            with_test_playbook=fake_test_playbook["id_set"]
        )

        content_packs_to_install = collect_content_packs_to_install(
            id_set=fake_id_set,
            integration_ids={great_integration_name},
            playbook_names={"fake_playbook"},
            script_names={"fake-script"}
        )

        assert content_packs_to_install == {great_pack_name, "FakePack"}
        assert not collect_tests_and_content_packs._FAILED
    finally:
        TestUtils.delete_files([
            fake_integration["path"]
        ])

        collect_tests_and_content_packs._FAILED = False


def test_collect_test_playbooks():
    """
    Given
    - Modified playbook list

    When
    - Collecting content packs to install - running `get_test_list_and_content_packs_to_install()`.
    Then
    - Finds all tests playbooks of the modified playbooks and returns the former pack names
    """

    test_conf = TestConf(MOCK_CONF)
    content_packs = test_conf.get_packs_of_collected_tests(['fake_playbook_in_fake_pack',
                                                            'TestCommonPython'], MOCK_ID_SET)
    assert 'FakePack' in content_packs


def test_collect_test_playbooks_no_results():
    """
    Given
    - Modified playbook list with no test playbooks

    When
    - Collecting content packs to install - running `get_test_list_and_content_packs_to_install()`.
    Then
    - returns an empty set
    """

    test_conf = TestConf(MOCK_CONF)
    content_packs = test_conf.get_packs_of_collected_tests(['TestCommonPython'], MOCK_ID_SET)
    assert set() == content_packs
