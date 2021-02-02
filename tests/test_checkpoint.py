# Copyright 2019 Splunk, Inc.
#
# Use of this source code is governed by a BSD-2-clause-style
# license that can be found in the LICENSE-BSD2 file or at
# https://opensource.org/licenses/BSD-2-Clause
import random

from jinja2 import Environment

from .sendmessage import *
from .splunkutils import *
from .timeutils import *
import pytest

env = Environment()

#
# Oct 8 15:00:25 DEVICENAME time=1570561225|hostname=devicename|severity=Informational|confidence_level=Unknown|product=IPS|action=Drop|ifdir=inbound|ifname=bond2|loguid={0x5d9cdcc9,0x8d159f,0x5f19f392,0x1897a828}|origin=1.1.1.1|time=1570561225|version=1|attack=Streaming Engine: TCP Segment Limit Enforcement|attack_info=TCP segment out of maximum allowed sequence. Packet dropped.|chassis_bladed_system=[ 1_3 ]|dst=10.10.10.10|origin_sic_name=CN=something_03_local,O=devicename.domain.com.p7fdbt|performance_impact=0|protection_id=tcp_segment_limit|protection_name=TCP Segment Limit Enforcement|protection_type=settings_tcp|proto=6|rule=393|rule_name=10.384_..|rule_uid={9F77F944-8DD5-4ADF-803A-785D03B3A2E8}|s_port=46455|service=443|smartdefense_profile=Recommended_Protection_ded9e8d8ee89d|src=1.1.1.2|
def test_checkpoint_splunk_ips(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}-lm|severity=Informational|confidence_level=Unknown|product=IPS|action=Drop|ifdir=inbound|ifname=bond2|loguid={{ host }}{0x5d9cdcc9,0x8d159f,0x5f19f392,0x1897a828}|origin=1.1.1.1|time={{ epoch }}|version=1|attack=Streaming Engine: TCP Segment Limit Enforcement|attack_info=TCP segment out of maximum allowed sequence. Packet dropped.|chassis_bladed_system=[ 1_3 ]|dst=10.10.10.10|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|performance_impact=0|protection_id=tcp_segment_limit|protection_name=TCP Segment Limit Enforcement|protection_type=settings_tcp|proto=6|rule=393|rule_name=10.384_..|rule_uid={9F77F944-8DD5-4ADF-803A-785D03B3A2E8}|s_port=46455|service=443|smartdefense_profile=Recommended_Protection_ded9e8d8ee89d|src=1.1.1.2|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# $Oct 8 15:48:31 DEVICENAME time=1570564111|hostname=devicename|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time=1570564111|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN=something_03_local,O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11_..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|
def test_checkpoint_splunk_firewall(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}-lm|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={{ host }}{0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time={{ epoch }}|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11:..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


def test_checkpoint_splunk_firewall_noise(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}-lm|product=Firewall|action=Drop|ifdir=inbound|ifname=bond1|loguid={{ host }}-{0x5d9ce80f,0x8d0555,0x5f19f392,0x18982828}|origin=1.1.1.1|time={{ epoch }}|version=1|chassis_bladed_system=[ 1_1 ]|dst=10.10.10.10|inzone=External|origin_sic_name=CN={{ host }},O=devicename.domain.com.p7fdbt|outzone=Internal|proto=6|rule=402|rule_name=11:..|rule_uid={C8CD796E-7BD5-47B6-90CA-B250D062D5E5}|s_port=33687|service=23|src=1.1.1.2|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])
    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


def test_checkpoint_splunk_firewall2(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}-lm|severity=Medium|product=Firewall|action=Drop|ifdir=inbound|ifname=eth1|loguid={{ host }}{0x0,0x0,0x0,0x1}|origin=111.89.111.53|originsicname=CN\={{ host }},O\=cma-xx.xx.net.xx|sequencenum=64|time={{epoch}}|version=5|dst=10.11.11.11|inspection_category=anomaly|foo=bar: bat mark||\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


def test_checkpoint_vsplunk_firewall(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}-lm|severity=Medium|product=Firewall|action=Drop|ifdir=inbound|ifname=eth1|loguid={{ host }}{0x0,0x0,0x0,0x2}|origin=111.89.111.53|originsicname=CN\=blah-v_{{ host }},O\=cma-xx.xx.net.xx|sequencenum=64|time={{epoch}}|version=5|dst=10.11.11.11|inspection_category=anomaly|foo=bar: bat mark||\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME |hostname=DEVICENAME|product=mds-query-tool|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570641309|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login|
def test_checkpoint_splunk_mds(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "|hostname={{ host }}-lm|product=mds-query-tool|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME |hostname=DEVICENAME|product=CPMI Client|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570641173|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login
def test_checkpoint_splunk_cpmi(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "|hostname={{ host }}-lm|product=CPMI Client|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=localhost|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 12:01:16 DEVICENAME |hostname=DEVICENAME|product=WEB_API|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\=cp_mgmt,o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time=1570640578|version=5|administrator=tufinapi|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login
def test_checkpoint_splunk_web_api(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "|hostname={{ host }}-lm|product=WEB_API|action=Accept|ifdir=outbound|origin=1.1.1.1|2.2.2.2|originsicname=cn\={{ host }},o\=DEVICENAME.domain.com.p7fdbt|sequencenum=1|time={{ epoch }}|version=5|administrator=tufinapi|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log Out|operation_number=12|subject=Administrator Login\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# Oct  9 11:05:15 DEVICENAME time=1570633513|hostname=DEVICENAME|product=SmartConsole|action=Accept|ifdir=outbound|origin=1.1.1.1|4.4.4.4|sequencenum=1|time=1570633513|version=5|additional_info=Authentication method: Password based application token|administrator=psanadhya|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log In|operation_number=10|subject=Administrator Login|
def test_checkpoint_splunk_smartconsole(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}|product=SmartConsole|action=Accept|ifdir=outbound|origin=1.1.1.1|4.4.4.4|sequencenum=1|time={{ epoch }}|version=5|additional_info=Authentication method: Password based application token|administrator=psanadhya|client_ip=3.3.3.3|machine=DEVICENAME|operation=Log In|operation_number=10|subject=Administrator Login|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# <6>kernel: sd 2:0:0:0: SCSI error: return code = 0x00040000
def test_checkpoint_splunk_os(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))
    pid = random.randint(1000, 32000)

    mt = env.from_string(
        "{{ mark }}kernel: sd 2:0:0:0: SCSI error: return code = 0x{{pid}}\n"
    )
    message = mt.render(mark="<6>", pid=pid)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search earliest=-1m@m latest=+1m@m index=osnix "0x{{ pid }}" sourcetype="nix:syslog"'
    )
    search = st.render(host=host, pid=pid)

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1


# time=1586182935|hostname=xxxx-xxxx|product=Syslog|ifdir=inbound|loguid={0x0,0x0,0x0,0x0}|origin=10.0.0.164|sequencenum=3|time=1586182935|version=5|default_device_message=<134>ctasd[5665]: Save SenderId lists finished |facility=local use 0|
def test_checkpoint_splunk_os_nested(
    record_property, setup_wordlist, setup_splunk, setup_sc4s
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(
        "time={{ epoch }}|hostname={{ host }}|product=Syslog|ifdir=inbound|loguid={{ host }}{0x0,0x0,0x0,0x3}|origin=10.0.0.0|sequencenum=3|time={{ epoch }}|version=5|default_device_message=<134>ctasd[5665]: Save SenderId lists finished |facility=local use 0|\n"
    )
    message = mt.render(mark="<111>", host=host, bsd=bsd, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="nix:syslog"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

audit_product_events_with_originsicname = [
    'time={{ epoch }}|hostname={{ host }}|product=SmartConsole|action=Accept|ifdir=outbound|loguid={0x6006afb8,0x4,0xe03ea00a,0x23654691}|origin=10.160.62.222|originsicname=cn\=cp_mgmt,o\=gw-8be69c..ba5xxz|sequencenum=5|version=5|administrator=admin|client_ip=10.160.62.222|fieldschanges=4 Objects were changed|operation=Publish|sendtotrackerasadvancedauditlog=0|session_uid=e21b3b1a-b138-43d1-9a21-4735c0fb00f0|subject=Revision Control',
    'time={{ epoch }}|hostname={{ host }}|product=Scheduled system update|action=Accept|ifdir=outbound|loguid={0x5fe59cf9,0x0,0x6563a00a,0x3fffaefd}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=3|time={{ epoch }}|version=5|administrator=Scheduled system update|client_ip=10.160.99.101|domain_name=SMC User|session_name=APPI Update|session_uid=3facc3d9-3e80-464b-965a-4763e406dbbf|subject=Application Control & URL Filtering Update',
    'time={{ epoch }}|hostname={{ host }}|product=WEB_API|action=Accept|ifdir=outbound|loguid={0x5fe674d1,0x0,0x6563a00a,0x3fffaefd}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|client_ip=10.160.99.101|domain_name=SMC User|operation=Log Out|sendtotrackerasadvancedauditlog=0|subject=Administrator Logout',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Application Control|ifdir=outbound|loguid={0x60079df9,0x0,0x6563a00a,0x336ee68e}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|time={{ epoch }}|version=5|db_ver=21012001|update_status=updated',
    'time={{ epoch }}|hostname={{ host }}|product=System Monitor|ifdir=inbound|ifname=daemon|loguid={0x5ffebeb4,0x1,0x6563a00a,0x336ee68e}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=2|time={{ epoch }}|version=5',
    'time={{ epoch }}|hostname={{ host }}|product=Log Update|ifdir=inbound|loguid={0x5ffeb8a6,0x0,0x6563a00a,0x336ee68e}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=2|time={{ epoch }}|version=5|blade_name=Anti Bot & Anti Virus',
    'time={{ epoch }}|hostname={{ host }}|product=license-mgmt|action=Accept|ifdir=outbound|loguid={0x5ff7ead6,0x105,0x6563a00a,0x3453e809}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|time={{ epoch }}|version=5|administrator=localhost|client_ip=127.0.0.1|machine=gw-02bd87|operation=Create Object|operation_number=0|subject=Object Manipulation',
    'time={{ epoch }}|hostname={{ host }}|product=smart_event|action=Accept|ifdir=outbound|loguid={0x5ff7ead6,0x103,0x6563a00a,0x3453e809}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|time={{ epoch }}|version=5|administrator=localhost|audit_status=Failure|client_ip=127.0.0.1|machine=localhost|operation=Log In|subject=Administrator Login',
    'time={{ epoch }}|hostname={{ host }}|product=Endpoint Management|action=Drop|ifdir=inbound|loguid={0x60069850,0x0,0xe03ea00a,0x23654691}|origin=10.160.62.224|originsicname=cn\=cp_mgmt,o\=gw-8be69c..ba5xxz|sequencenum=2|version=5|audit_status=Success|endpointname=C7553927437.WORKGROUP|endpointuser=Administrator@C7553927437|operation=Access Key For Encryptor',
    'time={{ epoch }}|hostname={{ host }}|product=SmartView|action=Accept|ifdir=outbound|loguid={0x5ffc2989,0x0,0xe03ea00a,0x2a66d4c7}|origin=10.160.62.224|originsicname=cn\=cp_mgmt,o\=gw-8be69c..ba5xxz|sequencenum=1|version=5|administrator=admin|client_ip=127.0.0.1|machine=localhost|operation=Log In|operation_number=10|subject=Administrator Login',
];

audit_product_events_without_originsicname = [
    'time={{ epoch }}|hostname={{ host }}|severity=High|product=RAD|alert=alert|ifdir=inbound|ifname=daemon|loguid={0x5ff8b7c9,0x0,0x6563a00a,0x342067f2}|origin=10.160.99.101|sequencenum=1|time={{ epoch }}|reason=Failed to fetch Check Point resources. Couldn\'t resolve host name, check /opt/CPsuite-R81/fw1/log/rad_events/Errors/flow_20730_38_MAIN_CHILD For more details',
    'time={{ epoch }}|hostname={{ host }}|product=SmartDashboard|action=Accept|ifdir=outbound|loguid={0x5fe321a8,0x2a,0x6563a00a,0x3fffaefd}|origin=10.160.99.101|sequencenum=1|time={{ epoch }}|version=5|additional_info=ca-bundle.crt|administrator=admin|client_ip=10.160.99.102|machine=C1359997769|subject=File Operation',
    'time={{ epoch }}|hostname={{ host }}|product=System Monitor|ifdir=inbound|loguid={0x5ffef7d6,0x0,0x6563a00a,0x336ee68e}|origin=10.160.99.101|sequencenum=1|time={{ epoch }}|version=5|cp_component_name=Threat Extraction Engine|cp_component_version=12|operation_results=Succeeded|package_action=Install|system_application=AutoUpdater',
    'time={{ epoch }}|hostname={{ host }}|product=SmartEvent Client|ifdir=inbound|loguid={0x60069487,0x0,0xe03ea00a,0x23654691}|origin=10.160.62.224|sequencenum=1|version=5|status=Started|update_service=1|version=R80.40',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Core|ifdir=inbound|loguid={0x6000eef3,0x5,0xe03ea00a,0x2a66d4c7}|origin=10.160.62.224|sequencenum=16777215|version=1|event_type=Push Operation|op_guid={ae78a89e-3c48-4e4c-940b-ed23ee87cdbd}|op_type=Repair EP client|os_name=Windows Server 10.0 Standard Server Edition|os_version=10.0-14393-SP0.0-SMP|product_family=Endpoint|src=10.160.177.73|src_machine_name=C7553927437|src_user_name=Administrator',
];

@pytest.mark.parametrize("audit_event", audit_product_events_with_originsicname)
def test_checkpoint_audit_events_with_originsicname(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, audit_event
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(audit_event + "\n")
    message = mt.render(host=host, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search index=netops host="cp_mgmt" sourcetype="cp_log" source="cp:audit" _time={{ epoch }} _raw="{{ message }}"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset, message=message.replace('\\','\\\\').replace('|', '\|')
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

@pytest.mark.parametrize("audit_event2", audit_product_events_without_originsicname)
def test_checkpoint_audit_events_without_originsicname(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, audit_event2
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(audit_event2 + "\n")
    message = mt.render(host=host, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search index=netops host="{{ host }}" sourcetype="cp_log" source="cp:audit" _time={{ epoch }} _raw="{{ message }}"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset, message=message.replace('\\','\\\\').replace('|', '\|')
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

security_product_events_with_originsicname = [
    'time={{ epoch }}|hostname={{ host }}|severity=High|confidence_level=High|product=Anti-Virus|action=Detect|ifdir=outbound|ifname=eth0|loguid={0x19532d95,0x979f5a67,0x2350f78b,0x40d23913}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=1|time={{ epoch }}|dst=8.8.8.8|malware_action=DNS query for a site known to contain malware|malware_rule_id={A2B8ED86-C9D0-4B0E-9334-C3CFA223CFC2}|session_id={0x5fe63a69,0x4,0xdbc0fdd2,0xe4d0ac81}|src=5.5.5.5',
    'time={{ epoch }}|hostname={{ host }}|product=Firewall|action=Accept|ifdir=inbound|loguid={0x3f58042c,0x1e77df46,0x1f1d6712,0x2e0a1aad}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|time={{ epoch }}|dst=2.2.2.2|src=3.3.3.3',
    'time={{ epoch }}|hostname={{ host }}|severity=Critical|product=URL Filtering|ifdir=outbound|loguid={0x5fe62536,0x1,0x6563a00a,0x3fffaefd}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=3|time={{ epoch }}',
    'time={{ epoch }}|hostname={{ host }}|severity=Informational|product=IPS|action=Drop|ifdir=inbound|ifname=eth0|loguid={0x5d31915e,0x6d33e67b,0xd6c2bda1,0x880b3b39}|origin=10.160.99.101|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|time={{ epoch }}|attack=Streaming Engine: TCP SYN Modified Retransmission|dst=4.4.4.4',   
    'time={{ epoch }}|hostname={{ host }}|product=HTTPS Inspection|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=DLP|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=MTA|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=Anti Spam|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=Threat Extraction|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=Anti-Ransomware|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=Anti-Exploit|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=OS Exploit|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
    'time={{ epoch }}|hostname={{ host }}|product=Application|ifdir=inbound|loguid={0x5ff9b62e,0x0,0x6563a00a,0x342067f2}|origin=1.1.1.1|originsicname=cn\=cp_mgmt,o\=gw-02bd87..4zrt7d|sequencenum=5|time={{ epoch }}|version=5|description=HTTPS Inspection Trusted CAs|status=Started|update_service=1|version=2.0',
];

security_product_events_without_originsicname = [
    'time={{ epoch }}|hostname={{ host }}|severity=Critical|product=IPS|ifdir=outbound|loguid={0x5fe54ecd,0x0,0x6563a00a,0x3fffaefd}|origin=1.1.1.1|sequencenum=1|time={{ epoch }}',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Anti-Malware|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Endpoint Compliance|ifdir=inbound|loguid={0x60069d03,0x0,0xe03ea00a,0x23654691}|origin=1.1.1.1|policy_guid={5E122911-49AE-40ED-A91B-0B56576E4549}|policy_name=default_compliance_policy|policy_type=60|product_family=Endpoint|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator|user_name= |user_sid=S-1-5-21-1704411108-3626445783-306313190-500',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Media Encryption & Port Protection|action=Allow|ifdir=inbound|loguid={0x60069d02,0x35,0xe03ea00a,0x23654691}|origin=1.1.1.1|media_class_id={4d36e965-e325-11ce-bfc1-08002be10318}|product_family=Endpoint|reading_data_access=Allow|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator|user_name= |writing_data_access=Allow',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|confidence_level=High|product=Threat Emulation|action=Prevent|ifdir=inbound|loguid={0x6002cac9,0x5,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|description=Endpoint File Reputation prevented malicious file (21011822364438_inj.exe)|detected_on= |event_type=TE Event|file_name=21011822364438_inj.exe|local_time={{ epoch }}|log_id=4000|policy_number=1|product_family=Endpoint|protection_name=Gen.Rep.exe|protection_type=File Reputation|resource=C:\KB4\Rassim\DataDir\Tests\\12\\21011822364438_inj.exe|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Critical|confidence_level=Medium|product=Forensics|action=Prevent|ifdir=inbound|loguid={0x6002bd5b,0x0,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|sequencenum=1|version=1|additional_info= |attack_status=Dormant|policy_name=Default Forensics settings|product_family=Endpoint|protection_name=Gen.Rep.exe|protection_type=File Reputation|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator|suspicious_events=Remote Logon Internal: ; Valid Accounts: ; |user_name= ',
    'time={{ epoch }}|hostname={{ host }}|severity=Critical|confidence_level=High|product=Anti-Bot|action=Prevent|ifdir=inbound|loguid={0x5ffd6981,0x16,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|event_type=Anti Bot Event|policy_name=Default Anti-Bot settings|policy_number=1|process_username=Administrator|product_family=Endpoint|protection_name=Phishing.TC.aqbrwu|protection_type=URL Reputation|proxy_src_ip=3.3.3.3|src=4.4.4.4|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Informational|confidence_level=High|product=Zero Phishing|action=Detect|ifdir=inbound|loguid={0x5ffc205f,0xb,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|event_type=Phishing Event|product_family=Endpoint|protection_name=gen.ba.phishing|protection_type=Phishing Prevention|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Informational|confidence_level=High|product=Anti Spam|action=Detect|ifdir=inbound|loguid={0x5ffc205f,0xb,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|event_type=Phishing Event|product_family=Endpoint|protection_name=gen.ba.phishing|protection_type=Phishing Prevention|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Informational|confidence_level=High|product=Anti-Virus|action=Detect|ifdir=inbound|loguid={0x5ffc205f,0xb,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|event_type=Phishing Event|product_family=Endpoint|protection_name=gen.ba.phishing|protection_type=Phishing Prevention|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Informational|confidence_level=High|product=MTA|action=Detect|ifdir=inbound|loguid={0x5ffc205f,0xb,0xe03ea00a,0x2a66d4c7}|origin=1.1.1.1|event_type=Phishing Event|product_family=Endpoint|protection_name=gen.ba.phishing|protection_type=Phishing Prevention|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
];

@pytest.mark.parametrize("security_event", security_product_events_with_originsicname)
def test_checkpoint_security_events_with_originsicname(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, security_event
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(security_event + "\n")
    message = mt.render(host=host, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops sourcetype="cp_log" source="cp:security" _raw="{{ message }}"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset, message=message.replace('\\','\\\\').replace('|', '\|')
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

@pytest.mark.parametrize("security_event2", security_product_events_without_originsicname)
def test_checkpoint_security_events_without_originsicname(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, security_event2
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(security_event2 + "\n")
    message = mt.render(host=host,epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log" source="cp:security" _raw="{{ message }}"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset, message=message.replace('\\','\\\\').replace('|', '\|') 
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1

network_product_dummy_events=[
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=IOS Profile|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Device|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=WIFI|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Cellular|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Text Message|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Network Access|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=VPN|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
    'time={{ epoch }}|hostname={{ host }}|severity=Low|product=Mobile|ifdir=inbound|loguid={0x60069d02,0x2e,0xe03ea00a,0x23654691}|origin=1.1.1.1|sequencenum=1|version=1|action_details=Started|scanned_drives=C:\|sig_ver=202012122231|src=2.2.2.2|src_machine_name=C7553927437|src_user_name=Administrator',
];

@pytest.mark.parametrize("network_event", network_product_dummy_events)
def test_checkpoint_network_events_without_originsicname(
    record_property, setup_wordlist, setup_splunk, setup_sc4s, network_event
):
    host = "{}-{}".format(random.choice(setup_wordlist), random.choice(setup_wordlist))

    dt = datetime.datetime.now()
    iso, bsd, time, date, tzoffset, tzname, epoch = time_operations(dt)

    # Tune time functions for Checkpoint
    epoch = epoch[:-7]

    mt = env.from_string(network_event + "\n")
    message = mt.render(host=host, epoch=epoch)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=netops host="{{ host }}" sourcetype="cp_log" source="cp:network" _raw="{{ message }}"'
    )
    search = st.render(
        epoch=epoch, bsd=bsd, host=host, date=date, time=time, tzoffset=tzoffset, message=message.replace('\\','\\\\').replace('|', '\|')
    )

    resultCount, eventCount = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", resultCount)
    record_property("message", message)

    assert resultCount == 1