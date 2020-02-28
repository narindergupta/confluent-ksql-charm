# Confluent-schema-regostry-charm

This charm will deploy confulent Schema Registry from deb package.

# Building

    cd src/confluent-schema-registry
    charm build

Will build the Kafka charm, and then the charm in `/tmp/charm-builds`.

# Operating

This charm uses the repository from confulent. It relates to zookeeper and

    juju deploy /tmp/charm-builds/confluent-schema-registry
    juju deploy zookeeper
    juju relate kafka zookeeper

# Notes

The confulent Schema Registry charm requires at least 4GB of memory.

# Details

Much of the charm implementation is borrowed from the Apache kafka
charm, but it's been heavily simplified and pared down. Jinja templating is
used instead of Puppet, and a few helper functions that were imported from
libraries are inlined.

---
