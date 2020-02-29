#!/bin/bash

set -eu

export PATH=/usr/lib/jvm/default-java/bin:$PATH

if [ -e "/etc/ksql/broker.env" ]; then
    . /etc/ksql/broker.env
fi

/usr/bin/ksql-server-start /etc/ksql/ksql-server.properties
