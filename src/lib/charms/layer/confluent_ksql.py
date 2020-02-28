# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import shutil
import re
import socket

from pathlib import Path
from base64 import b64encode, b64decode

from charmhelpers.core import hookenv, host
from charmhelpers.core.templating import render

from charms.reactive.relations import RelationBase

from charms import apt

KSQL = 'confluent-ksql'
KSQL_SERVICE = '{}.service'.format(KSQL)
KSQL_DATA = '/etc/ksql/'
KSQL_CONF = '/lib/systemd/system/'
KSQL_PORT = 8088
ca_crt_path = '/usr/local/share/ca-certificates/confluent-ksql.crt'
cert_path = Path('/etc/ksql/')
server_crt_path = cert_path / 'server.crt'
server_key_path = cert_path / 'server.key'
client_crt_path = cert_path / 'client.crt'
client_key_path = cert_path / 'client.key'


class Ksql(object):
    def install(self):
        '''
        Generates ksql.properties with the current
        system state.
        '''
        config = hookenv.config()
        log_dir = config['log_dir']

        context = {
            'keystore_password': keystore_password(),
            'ca_keystore': os.path.join(
                KSQL_DATA,
                'confluent_ksql.server.truststore.jks'
            ),
            'server_keystore': os.path.join(
                KSQL_DATA,
                'confluent_ksql.server.jks'
            ),
            'client_keystore': os.path.join(
                KSQL_DATA,
                'confluent_ksql.client.jks'
            ),
            'reghostname': hookenv.unit_private_ip(),
            'kafka_bootstrap': config['kafka_bootstrap'],
            'listeners': config['web_listen_uri'],
            'confluent_schema_url': config['confluent_schema_url'],
            'log_dir': log_dir
        }

        os.makedirs(log_dir, mode=0o770, exist_ok=True)
        shutil.chown(log_dir, user='cp-ksql', group='confluent')

        render(
            source='ksql-server.properties',
            target=os.path.join(KSQL_DATA, 'ksql-server.properties'),
            owner='root',
            perms=0o644,
            context=context
        )

        render(
            source='connect.properties',
            target=os.path.join(KSQL_DATA, 'connect.properties'),
            owner='root',
            perms=0o644,
            context=context
        )

        extraconfig = b64decode(config['extra_config']).decode("utf-8")
        with open(os.path.join(KSQL_DATA, 'ksql-server.properties'), "a") as outfile:
            outfile.write(extraconfig)
            outfile.close()

        self.restart()

    def restart(self):
        '''
        Restarts the registry service.
        '''
        host.service_restart(KSQL_SERVICE)

    def start(self):
        '''
        Starts the registry service.
        '''
        host.service_reload(KSQL_SERVICE)

    def stop(self):
        '''
        Stops the registry service.

        '''
        host.service_stop(KSQL_SERVICE)

    def is_running(self):
        '''
        Restarts the registry service.
        '''
        return host.service_running(KSQL_SERVICE)

    def version(self):
        '''
        Will attempt to get the version from the version fieldof the
        registry application.

        If there is a reader exception or a parser exception, unknown
        will be returned
        '''
        return apt.get_package_version(KSQL) or 'unknown'


def keystore_password():
    path = os.path.join(
        KSQL_DATA,
        'keystore.secret'
    )
    config = hookenv.config()
    if not os.path.isfile(path):
        with os.fdopen(
                os.open(path, os.O_WRONLY | os.O_CREAT, 0o440),
                'wb') as f:
            if config['ssl_key_password']:
                token = config['ssl_key_password'].encode("utf-8")
            else:
                token = b64encode(os.urandom(32))
            f.write(token)
            password = token.decode('ascii')
    else:
        password = Path(path).read_text().rstrip()
    return password


def resolve_private_address(addr):
    IP_pat = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    contains_IP_pat = re.compile(r'\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}')
    if IP_pat.match(addr):
        return addr  # already IP
    try:
        ip = socket.gethostbyname(addr)
        return ip
    except socket.error as e:
        hookenv.log(
            'Unable to resolve private IP: %s (will attempt to guess)' %
            addr,
            hookenv.ERROR
        )
        hookenv.log('%s' % e, hookenv.ERROR)
        contained = contains_IP_pat.search(addr)
        if not contained:
            raise ValueError(
                'Unable to resolve private-address: {}'.format(addr)
            )
        return contained.groups(0).replace('-', '.')


def get_ssl_certificate(self):
    """Get the PEM certificate to send to HAproxy through the relation.

    In case no certificate is defined, we send the "DEFAULT" keyword
    instead.
    """
    config = hookenv.config()
    ssl_cert = config.get("ssl-cert", "")
    ssl_key = config.get("ssl-key", "")

    if ssl_cert == "":
        # If no SSL certificate is specified, simply return "DEFAULT".
        hookenv.log(
            "No SSL configuration keys found, asking HAproxy to use the"
            " 'DEFAULT' certificate.")
        return ["DEFAULT"]

    if ssl_key == "":
        # A cert is specified, but no key. Error out.
        hookenv.log(
            'ssl key is blank',
            hookenv.ERROR
        )

    try:
        decoded_cert = base64.b64decode(ssl_cert)
        decoded_key = base64.b64decode(ssl_key)
    except TypeError:
        hookenv.log(
            'SSL certificate is invalid',
            hookenv.ERROR
        )

    decoded_pem = "%s\n%s" % (decoded_cert, decoded_key)

    hookenv.log(
        "Asking HAproxy to use the supplied 'ssl-cert' and 'ssl-key'"
        " parameters.")

    # Return the base64 encoded pem.
    return [base64.b64encode(decoded_pem)]


def resolve_private_address(addr):
    IP_pat = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    contains_IP_pat = re.compile(r'\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3}')
    if IP_pat.match(addr):
        return addr  # already IP
    try:
        ip = socket.gethostbyname(addr)
        return ip
    except socket.error as e:
        hookenv.log(
            'Unable to resolve private IP: %s (will attempt to guess)' %
            addr,
            hookenv.ERROR
        )
        hookenv.log('%s' % e, hookenv.ERROR)
        contained = contains_IP_pat.search(addr)
        if not contained:
            raise ValueError(
                'Unable to resolve private-address: {}'.format(addr)
            )
        return contained.groups(0).replace('-', '.')


def get_ingress_address(binding):
    try:
        network_info = hookenv.network_get(binding)
    except NotImplementedError:
        network_info = []

    if network_info and 'ingress-addresses' in network_info:
        # just grab the first one for now, maybe be more robust here?
        return network_info['ingress-addresses'][0]
    else:
        # if they don't have ingress-addresses they are running a juju that
        # doesn't support spaces, so just return the private address
        return hookenv.unit_get('private-address')
