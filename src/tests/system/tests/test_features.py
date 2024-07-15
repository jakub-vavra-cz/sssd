"""
SSSD Feature presence suite

:requirement: features
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


def get_sssd_version(client: Client):
    """
    Pull sssd version from client

    :return: Tuple of major, minor, rest of the version
    :rtype: tuple
    """
    ver = client.host.ssh.run(r'rpm -q sssd | grep -Eo "[0-9]+\.[0-9]+\.[0-9]+.*"').stdout
    major = int(ver.split(".", 1)[0])
    minor = int(ver.split(".", 2)[1])
    rest = ver.split(".", 2)[2]
    return major, minor, rest


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__sss_ssh_knownhosts(client: Client):
    """
    :title: Feature sss_ssh_knownhosts presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check sss_ssh_knownhosts feature presence
    :expectedresults:
        1. The feature is present in sssd 2.10 and higher
    :customerscenario: False
    :requirement: Support 'KnownHostsCommand' and deprecate 'sss_ssh_knownhostsproxy'
    """
    major, minor, rest = get_sssd_version(client)
    if (major == 2 and minor >= 10) or major > 2:
        assert not client.features["knownhostsproxy"]
    else:
        assert client.features["knownhostsproxy"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__files_provider(client: Client):
    """
    :title: Feature files-provider presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check files-provider feature presence
    :expectedresults:
        1. The feature should not be present in sssd 2.10 and higher
    :customerscenario: False
    """
    major, minor, _ = get_sssd_version(client)
    if (major == 2 and minor >= 10) or major > 2:
        assert not client.features["files-provider"]
    else:
        assert client.features["files-provider"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__passkey(client: Client):
    """
    :title: Feature passkey presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check passkey feature presence
    :expectedresults:
        1. The feature should be on RHEL 9.4+, CentOS 9+, Fedora 39+ and Ubuntu 23.10+
    :customerscenario: False
    :requirement: passkey
    """
    expect_passkey = False
    if "Fedora" in client.distro_name:
        expect_passkey = client.distro_major >= 39
    elif "Red Hat Enterprise Linux" in client.distro_name:
        expect_passkey = not (client.distro_major <= 8 or (client.distro_major == 9 and client.distro_minor < 4))
    elif "CentOS Stream" in client.distro_name:
        expect_passkey = client.distro_major >= 9
    elif "Ubuntu" in client.distro_name:
        expect_passkey = not (client.distro_major <= 23 or (client.distro_major == 23 and client.distro_minor < 10))
    else:
        pytest.skip("Unknown distro, no expectations set for passkey feature presence")

    assert bool(
        client.features["passkey"] == expect_passkey
    ), f"Passkey deos not match expectations on {client.distro_name} {client.distro_major} {client.distro_minor}."


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__ldap_use_ppolicy(client: Client):
    """
    :title: Feature ldap_use_ppolicy presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check ldap_use_ppolicy feature presence
    :expectedresults:
        1. The feature should be present in sssd 2.10 and higher
    :customerscenario: False
    """
    major, minor, rest = get_sssd_version(client)
    if (major == 2 and minor >= 10) or major > 2:
        assert client.features["ldap_use_ppolicy"]
    else:
        assert not client.features["ldap_use_ppolicy"]


@pytest.mark.importance("high")
@pytest.mark.topology(KnownTopology.Client)
def test_feature__non_privileged(client: Client):
    """
    :title: Feature non-privileged presence
    :setup:
        1. Make sure sssd is installed
    :steps:
        1. Check non-privileged feature presence
    :expectedresults:
        1. The feature should be present in sssd 2.10 and higher
    :customerscenario: False
    """
    major, minor, rest = get_sssd_version(client)
    if (major == 2 and minor >= 10) or major > 2:
        assert client.features["non-privileged"]
    else:
        assert not client.features["non-privileged"]
