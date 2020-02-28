# Overview

Confluent Schema Registry provides a RESTful interface for developers to define
standard schemas for their events, share them across the organization and safely
 evolve them in a way that is backward compatible and future proof.

Schema Registry stores a versioned history of all schemas and allows the
evolution of schemas according to the configured compatibility settings. It also
provides a plugin to clients that handles schema storage and retrieval for
messages that are sent in Avro format.

This charm will relate to zookeeper for kafka integration. Also for certificates
it will use easyrsa or vault as both provide tls-certificate interfaces.

This charm provides Confluent Schema Registry service.

Also remember to check the [icon guidelines][] so that your charm looks good
in the Juju GUI.

# Usage

juju deploy confulent-schema-registry
juju deploy -n 3 zookeeper
juju deploy -n 3 kafka
juju deploy easyrsa

confulent-schema-registry listens on all IP address at port 8081.

## Known Limitations and Issues

This is experimental version of charm.

# Configuration

default configurations in the charm used to give you deployment and configuration
out of box but you can change the configutation
juju config confulent-schema-registry

# Contact Information

Narinder Gupta narinder.gupta@canonical.com

## Confluent Schema Registry

  - https://www.confluent.io/confluent-schema-registry


[service]: http://example.com
[icon guidelines]: https://jujucharms.com/docs/stable/authors-charm-icon
