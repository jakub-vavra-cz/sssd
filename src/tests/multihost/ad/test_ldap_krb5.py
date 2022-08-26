""" AD-Provider AD Ldap Krb5 tests ported from bash

:requirement: ldap_krb5
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:caseautomation: Automated
:testtype: functional
"""


import pytest
from pexpect import pxssh
from sssd.testlib.common.utils import sssdTools


@pytest.fixture(scope="class", name="configure_ldap_krb5")
def fixture_configure_ldap(session_multihost, request):
    """<TBD>"""
    hostname = session_multihost.client[0].run_command(
        'hostname', raiseonerr=False).stdout_text.rstrip()
    ad_realm = session_multihost.ad[0].domainname.upper()
    # Join AD manually to set the user-principal for sasl
    joincmd = f"realm join --user=Administrator --user-principal=host/" \
              f"{hostname}@{ad_realm} " \
              f"{session_multihost.ad[0].domainname.lower()}"
    session_multihost.client[0].run_command(
        joincmd, stdin_text=session_multihost.ad[0].ssh_password,
        raiseonerr=False)

    # backup common config
    session_multihost.client[0].run_command(
        'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.configure_ldap_krb5',
        raiseonerr=False
    )

    # Updating AD to have a lockout policy
    pwdpolicy = f"powershell.exe -inputformat none -noprofile "\
                f"'Set-ADDefaultDomainPasswordPolicy -Identity " \
                f"\"{session_multihost.ad[0].domainname}\" -LockoutDuration " \
                f"00:03:00 -LockoutObservationWindow 00:03:00 " \
                f"-LockoutThreshold 3'"
    session_multihost.ad[0].run_command(pwdpolicy, raiseonerr=False)

    # if rpm -q oddjob-mkhomedir >> /dev/null ; then
    #     authconfig --enablemkhomedir --updateall
    # else
    #     yum install -y oddjob oddjob-mkhomedir
    #     authconfig --enablemkhomedir --updateall
    # fi
    #
    # Setup sssd.conf for LDAP AUTH <TBD>
    client = sssdTools(session_multihost.client[0], session_multihost.ad[0])
    dom_section = f'domain/{client.get_domain_section_name()}'
    sssd_params = {
        'debug_level': '9',
        'id_provider': 'ldap',
        'ldap_uri': f'ldap://{session_multihost.ad[0].ip}',
        'ldap_schema':  'rfc2307bis',
        'ldap_default_bind_dn': f'CN=administrator,CN=Users'
                f',{session_multihost.ad[0].domain_basedn_entry}',
        'ldap_default_authtok_type': 'password',
        'ldap_default_authtok': f'{session_multihost.ad[0].ssh_password}',
        'ldap_search_base': f'CN=Users,'
                            f'{session_multihost.ad[0].domain_basedn_entry}',
        'ldap_user_object_class': 'user',
        'ldap_user_home_directory': 'unixHomeDirectory',
        'ldap_user_principal': 'userPrincipalName',
        'ldap_group_object_class': 'group',
        'ldap_force_upper_case_realm': 'True',
        'ldap_referrals': 'False',
        'ldap_tls_cacert': '/etc/openldap/certs/ad_cert.pem'
    }
    client.sssd_conf(dom_section, sssd_params)
    client.sssd_conf('nss', {'filter_groups': 'root', 'filter_users': 'root'})
    client.sssd_conf('sssd', {'services': 'nss, pam, ssh'})

    def unconfigure_ldap_krb5():
        """ Remove ldap configuration"""
        # Restore config so we can leave AD realm
        session_multihost.client[0].run_command(
            'cp -f /etc/sssd/sssd.conf.configure_ldap_krb5 /etc/sssd/sssd.conf',
            raiseonerr=False
        )
        session_multihost.client[0].run_command(
            f"realm leave {ad_realm}", raiseonerr=False)
    request.addfinalizer(unconfigure_ldap_krb5)


@pytest.mark.tier1_4
@pytest.mark.adldapkrb5
@pytest.mark.usefixtures("joinad")
class TestADLdapKrb5:
    """Automated Test Cases for AD LDAP krb5 ported from bash"""

    @staticmethod
    @pytest.skip("Test is no longer valid due to default hardening on AD.")
    def test_0001_ldap_no_ssl(multihost, create_aduser_group):
        """test_0001_ldap_no_ssl

        :title: IDM-SSSD-TC: ad_provider: ldap_krb5: Enumerate AD User
         user01 over LDAP without SSL
        :id:
        :setup:
          1. Configure sssd with ldap_user_principal = userPrincipalName
        :steps:
          1. Run getent passwd for the user.
        :expectedresults:
          1. User is found.
        :customerscenario: False
        """
        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent -s sss passwd {aduser}',
            raiseonerr=False
        )

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."

    @staticmethod
    def test_0002_ldap_starttls(multihost, create_aduser_group):
        """test_0002_ldap_starttls

        :title: IDM-SSSD-TC: ad_provider: ldap_krb5: Enumerate and Authenticate
         user01 over STARTTLS bz748833
        :id:
        :setup:
          1. Configure sssd a certificate
        :steps:
          1. Run getent passwd for the user.
          2. Run ssh for the user.
        :expectedresults:
          1. User is found.
          2. Ssh command succeeds.
        :customerscenario: False
        """
        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_use_start_tls': 'true',
        }
        client.sssd_conf(dom_section, sssd_params)

        client.clear_sssd_cache()

        # Create AD user
        (aduser, _) = create_aduser_group

        # Search for the user
        usr_cmd = multihost.client[0].run_command(
            f'getent passwd {aduser}',
            raiseonerr=False
        )

        # Run su command
        su_result = client.su_success(aduser)
        # Run ssh command
        ssh_result = client.auth_from_client(aduser, 'Secret123') == 3

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert usr_cmd.returncode == 0, f"User {aduser} was not found."
        assert su_result, "The su command failed!"
        assert ssh_result, "The ssh login failed!"



#
# rlPhaseStartTest "Enumerate and Authenticate user01 over STARTTLS bz748833"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_id_use_start_tls = true
#     ldap_uri = ldap://$AD_SERVER1
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
# sssd_restart_clean
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 0 "lkuser01-${JOBID} user returned as expected."
# rlLog "Login as lkuser01-${JOBID} to localhost using SSH"
# rlRun "ssh_user_password_login lkuser01-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "AD user authentication with GSSAPI only"
# #bz1659507
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldap://$AD_SERVER1
#     ldap_schema = ad
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
#     ldap_sasl_mech = GSSAPI
#     krb5_server = $AD_SERVER1
# " > /etc/sssd/sssd.conf
# sssd_restart_clean
# rlLog "Login as lkuser01-${JOBID} to localhost using SSH"
# rlRun "ssh_user_password_login lkuser01-${JOBID} Secret123"
# sssd_restart_clean
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 0 "lkuser01-${JOBID} user returned as expected."
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate and Authenticate user01 over LDAPS"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_schema = AD
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
# sssd_restart_clean
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 0 "lkuser01-${JOBID} user returned as expected."
# rlLog "Login as lkuser01-${JOBID} to localhost using SSH"
# rlRun "ssh_user_password_login lkuser01-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "Authenticate lkuser01 over KRB5"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_schema = AD
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     auth_provider = krb5
#     krb5_realm = $AD_SERVER1_REALM
#     krb5_server = $AD_SERVER1
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
# sssd_restart_clean
#
# rlRun "su_success lkuser01-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "Lookup valid LDAP Groups"
# rlLog "Looking up group lkgroup01-${JOBID}."
# rlRun "getent group lkgroup01-${JOBID}" 0 "lkgroup01-${JOBID} group returned as expected."
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate user belonging to multiple groups"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_schema = AD
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
#
# rlRun "getent -s sss group lkgroup011-${JOBID}"
# rlRun "id lkuser01-${JOBID} | grep lkgroup01-${JOBID} | grep lkgroup011-${JOBID}"
# rlRun "id -g lkuser01-${JOBID} | grep 10${JOBID}"
# rlRun "su_success lkuser01-${JOBID} Secret123"
#
# # Setup sssd to lookup posix users and groups
# # Reproducer for bug 1165240
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     id_provider = ldap
#     ldap_schema = rfc2307bis
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_user_object_class = user
#     ldap_user_home_directory = unixHomeDirectory
#     ldap_user_principal = userPrincipalName
#     ldap_group_object_class = group
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
# rlRun "id lkuser01-${JOBID} | grep lkgroup01-${JOBID} | grep lkgroup011-${JOBID}"
# rlRun "id -g lkuser01-${JOBID} | grep 10${JOBID}"
# rlRun "su_success lkuser01-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate user belonging to nested groups"
#
# rlRun "getent -s sss group lkgroup012-${JOBID}"
# rlRun "id lkuser01-${JOBID} | grep lkgroup012-${JOBID} | grep lkgroup01-${JOBID}"
# rlRun "su_success lkuser01-${JOBID} Secret123"
#
# rlLog "Verify bz871843"
# sssd_restart_clean
# rlRun "getent group lkgroup01-${JOBID}"
# rlRun "getent group lkgroup012-${JOBID}"
# rlRun "id lkuser01-${JOBID} | grep lkgroup012 | grep lkgroup01"
#
# rlLog "Verify bz872110"
# sssd_restart_clean
# rlRun "getent group lkgroup012-${JOBID}"
# rlRun "getent group lkgroup01-${JOBID} | grep -v \"lkuser01-${JOBID},lkuser01-${JOBID}\""
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate user without UNIX attributes belonging to nested groups and intermediate groups bz748822"
#
# > /var/log/sssd/sssd_AD.log
#
# rlRun "getent -s sss group lkgroup032-${JOBID} | awk -F: '{print $4}' | grep lkuser03-${JOBID}"
# rlRun "id lkuser03-${JOBID} | grep lkgroup032-${JOBID} | grep lkgroup03-${JOBID}"
# rlRun "getent -s sss group lkgroup031-${JOBID}" 2 "Unable to enumerate a non-posix group lkgroup031-${JOBID}"
# rlAssertNotGrep "no gid provided for \[lkgroup031-${JOBID}\] in domain" "/var/log/sssd/sssd_AD.log"
# rlAssertNotGrep "Failed to build search request: Operations error" "/var/log/sssd/sssd_AD.log"
# rlRun "su_success lkuser03-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate non existing user"
# rlRun "getent -s sss passwd invalid_user" 2 "Enumeration fails for Invalid User"
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate non existing group"
# rlRun "getent -s sss group invalid_group" 2 "Enumeration fails for Invalid Group"
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate valid user and group with id less than min id bz692455"
# echo "min_id = 2147483647" >> /etc/sssd/sssd.conf
#
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
#
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 2 "Enumeration fails since uid number of user is less than min_id=2147483647"
# rlAssertGrep "id out of range" "/var/log/sssd/sssd_AD.log"
#
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
#
# rlRun "getent -s sss group lkgroup02-${JOBID}" 2 "Enumeration fails as expected since gid number of group is less than min_id=2147483647"
# rlRun "getent -s sss group lkgroup01-${JOBID}" 2 "Enumeration fails as expected since gid number of group is less than min_id=2147483647(check bug 692455 if this Fails)"
# rlAssertGrep "id out of range" "/var/log/sssd/sssd_AD.log"
# rlPhaseEnd
#
# rlPhaseStartTest "Enumerate valid user and group with id more than max id bz692455"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     max_id = 10000
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
#
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 2 "Enumeration fails as expected since uid number is more than the max_id=10000"
# rlAssertGrep "id out of range" "/var/log/sssd/sssd_AD.log"
#
# > /var/log/sssd/sssd_AD.log
# rlRun "getent -s sss group lkgroup01-${JOBID}" 2 "Enumeration fails as expected since the gid number is more than the max_id=10000(check bug 692455 if this Fails)"
# rlAssertGrep "id out of range" "/var/log/sssd/sssd_AD.log"
# rlPhaseEnd
#
# rlPhaseStartTest "Check with ldap access filter"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     access_provider = ldap
#     ldap_access_filter = (uidNumber=10${JOBID})
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
# sleep 15
# rlRun "getent -s sss passwd lkuser02-${JOBID}" 0 "Enumeration succeeds for lkuser02-${JOBID} as expected"
# rlRun "su_fail lkuser02-${JOBID} Secret123"
# rlAssertGrep "was not found with the specified filter. Denying access" "/var/log/sssd/sssd_AD.log"
# rlRun "su_success lkuser01-${JOBID} Secret123"
# rlPhaseEnd
#
#
# rlPhaseStartTest "Check with ldap access filter and global character"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_schema = AD
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     access_provider = ldap
#     ldap_access_filter = (cn=*02-${JOBID})
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
# sleep 15
# rlRun "getent -s sss passwd lkuser01-${JOBID}" 0 "Enumeration succeeds for lkuser01-${JOBID} as expected"
# rlRun "su_fail lkuser01-${JOBID} Secret123"
# rlAssertGrep "was not found with the specified filter. Denying access" "/var/log/sssd/sssd_AD.log"
# rlRun "getent -s sss passwd lkuser02-${JOBID}" 0 "Enumeration succeeds for lkuser02-${JOBID} as expected"
# rlRun "su_success lkuser02-${JOBID} Secret123"
# rlPhaseEnd
#
# rlPhaseStartTest "Check when ldap sasl mech set to GSSAPI"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     id_provider = ldap
#     ldap_uri = ldap://$AD_SERVER1
#     ldap_schema = ad
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     auth_provider = krb5
#     krb5_server = $AD_SERVER1
#     krb5_realm = $AD_SERVER1_REALM
#     ldap_sasl_mech = GSSAPI
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
# rlRun "sleep 10"
#
# rlRun "getent passwd lkuser01-${JOBID}"
#
# # Automation for BZ 966556 GSSAPI working only on first login
# for i in {1..5}; do
#     rlRun "su_success lkuser01-${JOBID} Secret123"
#     sleep 5
# done
# rlPhaseEnd
#
# rlPhaseStartTest "Check login for disabled AD user account"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     sbus_timeout = 30
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     description = LDAP domain with AD server
#     id_provider = ldap
#     ldap_uri = ldaps://$AD_SERVER1
#     ldap_tls_cacert = /etc/openldap/certs/ad_cert.pem
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     access_provider = ldap
#     ldap_access_order = expire
#     ldap_account_expire_policy=ad
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
#
# # Generating pub key for password-less auth
# rm -f /root/.ssh/id_rsa*
# ssh-keygen -t rsa -f /root/.ssh/id_rsa -P ''
# mkdir -p /home/lkuser04-${JOBID}/.ssh
# cat /root/.ssh/id_rsa.pub >> /home/lkuser04-${JOBID}/.ssh/authorized_keys
# restorecon -v /home/lkuser04-${JOBID}/.ssh/authorized_keys
#
# > /var/log/secure
# rlRun "ssh -l lkuser04-${JOBID} localhost" 255 "Expected: fails to login as lkuser04-${JOBID}"
# sleep 2
# rlAssertGrep "The user account is disabled on the AD server" "/var/log/secure"
# rlPhaseEnd
#
# rlPhaseStartTest "Check Active Directory Account Lockout for expired user"
#
# rlRun "getent -s sss passwd lkuser05-${JOBID}" 0 "Enumeration succeeds for lkuser05-${JOBID} as expected"
#
# rm -f /root/.ssh/id_rsa*
# ssh-keygen -t rsa -f /root/.ssh/id_rsa -P ''
# mkdir -p /home/lkuser05-${JOBID}/.ssh
# cat /root/.ssh/id_rsa.pub >> /home/lkuser05-${JOBID}/.ssh/authorized_keys
# restorecon /home/lkuser05-${JOBID}/.ssh/authorized_keys
#
# > /var/log/sssd/sssd_AD.log
# > /var/log/secure
# sssd_restart_clean
#
# rlRun "ssh -l lkuser05-${JOBID} localhost" 255 "login as lkuser05-${JOBID} fails as expected"
# sleep 2
# rlAssertGrep "The user account is expired on the AD server" "/var/log/secure"
# rlPhaseEnd
#
# rlPhaseStartTest "Check GECOS Fallback to cn"
#
# rlRun "getent -s sss passwd lkuser06-${JOBID} | awk -F: '{print \$5}' | grep \"LKUSER06-${JOBID} GECOS\""
#
# unindent <<<"
#     dn: cn=lkuser06-${JOBID},cn=Users,$AD_SERVER1_BASEDN
#     changetype: modify
#     delete: gecos
# " | ldapmodify "${LDAP_OPTS_SERVER1[@]}" || die failed to delete attribute gecos
#
# sssd_restart_clean
# rlRun "sleep 10"
#
# rlRun "getent -s sss passwd lkuser06-${JOBID} | awk -F: '{print \$5}' | grep lkuser06-${JOBID}"
# rlRun "su_success lkuser06-${JOBID} Secret123"
# rlRun "getent -s sss passwd lkuser06-${JOBID} | awk -F: '{print \$5}' | grep lkuser06-${JOBID}"
# rlPhaseEnd
#
# rlPhaseStartTest "Users lacking posix attribute breaks group lookup bz791208"
# > /var/log/sssd/sssd_AD.log
# sssd_restart_clean
#
# rlRun "getent -s sss group lkgroup07-${JOBID}"
# rlAssertNotGrep "Failed to save the user - entry has no name attribute" "/var/log/sssd/sssd_AD.log"
# rlAssertNotGrep "Failed to save user" "/var/log/sssd/sssd_AD.log"
# rlPhaseEnd
#
# rlPhaseStartTest "Lookup users and groups with backslash and comma bz683158"
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     id_provider = ldap
#     ldap_uri = ldap://$AD_SERVER1
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
#
# rlRun "getent -s sss group lkgroup08-${JOBID}"
# rlPhaseEnd
#
# rlPhaseStartTest "Allow SSSD to notify user of denial due to AD account lockout bz1264705"
# # Tests the 'pam_account_lockout_message' parameter, this only works when provider = ldap, and only
# # su attempts and not SSH. Lastly the AD server must have a lockout policy, this test expects 3
# # failed login attempts will lock the account out, disabling the account will not trigger this
# # message.
# unindent <<<"
#     [sssd]
#     config_file_version = 2
#     services = nss, pam
#     domains = AD
#
#     [nss]
#     filter_groups = root
#     filter_users = root
#
#     [pam]
#     pam_account_locked_message = You are locked
#
#     [domain/AD]
#     debug_level = 0xFFF0
#     id_provider = ldap
#     ldap_uri = ldap://$AD_SERVER1
#     ldap_schema = ad
#     ldap_default_bind_dn = $AD_SERVER1_BINDDN
#     ldap_default_authtok = $AD_SERVER1_BINDPASS
#     ldap_search_base = $AD_SERVER1_BASEDN
#     ldap_force_upper_case_realm = True
#     ldap_referrals = false
#     ldap_schema = rfc2307bis
#     ldap_user_name = sAMAccountName
#     ldap_user_search_base = CN=users,$AD_SERVER1_BASEDN
#     ldap_user_object_class = user
#     ldap_user_home_directory = unixHomeDirectory
#     ldap_user_principal = sAMAccountName
#     ldap_group_search_base = CN=users,$AD_SERVER1_BASEDN
#     ldap_group_object_class = group
#     ldap_force_upper_case_realm = true
# " > /etc/sssd/sssd.conf
#
# sssd_restart_clean
#
# rlRun "su_success lkuser01-${JOBID} Secret123"
# rlRun "su_fail lkuser01-${JOBID} fail01"
# rlRun "su_fail lkuser01-${JOBID} fail02"
# rlRun "su_fail lkuser01-${JOBID} fail03"
# rlRun "su_fail_log lkuser01-${JOBID} Secret123 | grep 'You are locked'"
#
# rlPhaseEnd


