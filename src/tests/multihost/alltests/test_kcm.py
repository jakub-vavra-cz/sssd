"""Automation of kcm related bugs

:requirement: IDM-SSSD-REQ :: SSSD KCM as default Kerberos CCACHE provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import pytest
import time
from pexpect import pxssh
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.kcm
class TestKcm(object):
    """
    This is for kcm bugs automation
    """
    @pytest.mark.tier1_2
    def test_client_timeout(self, multihost, backupsssdconf):
        """
        :title: kcm: Increase client idle
         timeout to 5 minutes
        :id: 6933cb85-1616-4b7f-a049-e81ab4c05347
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1884205
        """
        client = sssdTools(multihost.client[0])
        domain_params = {'debug_level': '9'}
        client.sssd_conf('kcm', domain_params)
        multihost.client[0].service_sssd('restart')
        user = 'foo1@example1'
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        client.login(login_timeout=30, sync_multiplier=5,
                     auto_prompt_reset=False)
        sssdTools(multihost.client[0]).clear_sssd_cache()
        multihost.client[0].run_command("systemctl restart sssd-kcm")
        multihost.client[0].run_command("> /var/log/sssd/sssd_kcm.log")
        start_time = time.time()
        multihost.client[0].run_command("kinit foo1 <&- & ")
        end_time = time.time()
        client.logout()
        assert end_time - start_time >= 300
        grep_cmd = multihost.client[0].run_command("grep"
                                                   " 'Terminated"
                                                   " client'"
                                                   " /var/log/sssd/"
                                                   "sssd_kcm.log")
        assert 'Terminated client' in grep_cmd.stdout_text

    @pytest.mark.tier1_2
    def test_refresh_contain_timestamp(self,
                                       multihost,
                                       backupsssdconf):
        """
        :title: kcm: First smart refresh query contains
         modifyTimestamp even if the modifyTimestamp is 0
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1926454
        :customerscenario: true
        :id: 09f654c4-759d-11eb-bfff-002b677efe14
        :steps:
          1. Configure SSSD with sudo
          2. Leave ou=sudoers empty - do not define any rules
          3. See that smart refresh does not contain
             modifyTimestamp in the filter
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        ldap_params = {'domains': 'example1'}
        tools.sssd_conf('sssd', ldap_params)
        ldap_params = {'sudo_provider': 'ldap',
                       'ldap_sudo_smart_refresh_interval': '60'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), ldap_params)
        multihost.client[0].service_sssd('restart')
        multihost.client[0].run_command("> /var/log/sssd/sssd_example1.log")
        time.sleep(65)
        log_location = "/var/log/sssd/sssd_example1.log"
        grep_cmd = multihost.client[0].run_command(f"grep "
                                                   f"'calling "
                                                   f"ldap_search_ext with' "
                                                   f"{log_location}")
        assert 'modifyTimestamp>=' not in grep_cmd.stdout_text

    @pytest.mark.tier1_2
    def test_kcm_check_socket_path(self, multihost, backupsssdconf):
        """
        :title: kcm: Test socket path when sssd-kcm is activated by systemd
        :id: 6425bf2c-d07e-4d65-b15d-946141422f96
        :ticket: https://github.com/SSSD/sssd/issues/5406
        """
        # Start from a known-good state after removing log file and adding a
        # new socket path
        client = sssdTools(multihost.client[0])
        domain_log = '/var/log/sssd/sssd_kcm.log'
        multihost.client[0].service_sssd('stop')
        client.service_ctrl('stop', 'sssd-kcm')
        client.remove_sss_cache(domain_log)
        domain_params = {'debug_level': '9',
                         'socket_path': '/some_path/kcm.socket'}
        client.sssd_conf('kcm', domain_params)
        multihost.client[0].service_sssd('start')
        # After starting sssd-kcm, latest sssd_kcm.log will generate
        client.service_ctrl('start', 'sssd-kcm')
        # Give sssd some time to load
        time.sleep(2)
        # Check log file for the expected warning message
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = "Warning: socket path defined in systemd unit .*." \
              "and.sssd.conf...some_path.kcm.socket..don't.match"
        find = re.compile(r'%s' % msg)
        assert find.search(log)


    def test_kcm_switches_away(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: kcm_provider: Kcm switches away from newest ticket
        :id: 245ddaba-f99e-49ce-8e05-bef4008bdd12
        :setup:
         1. Create two user users.
         2. Clean up all tickets
         3. Install server with gui, enable graphical target, reboot
        :steps:
          1. Log into a machine and create a ticket for first user
          2. Log into a machine and create a ticket for second user
          3. Log into a machine and show tickets
          4. Login in gdm as foo1@test.example
          5. Run kswitch -p foo1 in a new terminal
          6. Lock and unlock workstation
          7. Run klist in the same terminal
        :expectedresults:
          1. Ticket for first user is created.
          2. Ticket second user is created.
          3. Ticket for second user is active.
          4. Logged in as foo1
          5. Credential is switched
          6. Gui is locked and unlocked
          7. Klist shows the credential foo1.
        :customerscenario: True
        :bugzilla:
           https://bugzilla.redhat.com/show_bug.cgi?id=2166943
           https://bugzilla.redhat.com/show_bug.cgi?id=2143925
        """
        multihost.client[0].run_command(
            'yum install -y oddjob-mkhomedir rsyslog krb5-workstation', raiseonerr=False)
        multihost.client[0].run_command(
            'systemctl enable oddjobd; systemctl start oddjobd;', raiseonerr=False)
        multihost.client[0].run_command(
            'yum groupinstall "Server with GUI" -y || yum groupinstall -y gnome-desktop',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            'systemctl set-default graphical', raiseonerr=False)
        multihost.client[0].run_command(
            'authconfig --enablemkhomedir --update || authselect select sssd with-mkhomedir --force',
            raiseonerr=False
        )
        multihost.client[0].run_command('reboot', raiseonerr=False)
        time.sleep(120)
        client = sssdTools(multihost.client[0])
        client.sssd_conf('kcm', {'debug_level': '9'})
        client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})
        user1 = f"foo1@example.test"
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'access_provider': 'simple',
            'simple_allow_users': 'foo1',
            'auth_provider': 'krb5',
            'id_provider': 'ldap',
            'chpass_provider': 'krb5',
            'krb5_realm': 'EXAMPLE.TEST',
            'krb5_server': multihost.master[0].sys_hostname,
            'fallback_homedir': '/home/%u',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        multihost.client[0].run_command("systemctl restart gdm || systemctl restart lightdm", raiseonerr=False)
        multihost.client[0].run_command(f"cat /etc/sssd/sssd.conf", raiseonerr=False)
        multihost.client[0].run_command(f"su - {user1} -c 'kdestroy -A'", raiseonerr=False)
        multihost.client[0].run_command(
             f"su - {user1} -c 'kinit -c KCM:14583101:12345 foo1'", stdin_text="Secret123", raiseonerr=False)
        multihost.client[0].run_command(f"su - {user1} -c 'klist -l'", raiseonerr=False)
        multihost.client[0].run_command(
             f"su - {user1} -c 'kinit -c KCM:14583101:23456 foo2'", stdin_text="Secret123", raiseonerr=False)
        multihost.client[0].run_command(f"su - {user1} -c 'klist -l'", raiseonerr=False)
        multihost.client[0].run_command(f"su - {user1} -c 'kswitch -p foo1'", raiseonerr=False)
        multihost.client[0].run_command(f"su - {user1} -c 'klist'", raiseonerr=False)
        assert False, """Use --pdb to stop here, proceed with manual testing."""
