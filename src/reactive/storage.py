import os

from charms.layer.confluent_ksql import Ksql

from charmhelpers.core import hookenv, unitdata

from charms.reactive import remove_state, hook, set_flag

from charmhelpers.core.hookenv import log


def init_brokerid(log_dir):
    broker_path = os.path.join(log_dir, '.broker_id')
    broker_id = hookenv.local_unit().split('/', 1)[1]

    if not os.path.exists(broker_path):
        os.makedirs(log_dir, exist_ok=True)

        with open(broker_path, 'w+') as f:
            f.write(broker_id)


@hook('logs-storage-attached')
def storage_attach():
    storageids = hookenv.storage_list('logs')
    if not storageids:
        hookenv.status_set('blocked', 'cannot locate attached storage')
        return
    storageid = storageids[0]

    mount = hookenv.storage_get('location', storageid)
    if not mount:
        hookenv.status_set('blocked', 'cannot locate attached storage mount')
        return

    log_dir = os.path.join(mount, "logs")
    unitdata.kv().set('confluent_ksql.storage.log_dir', log_dir)
    hookenv.log('confluent_ksql logs storage attached at {}'.format(log_dir))

    init_brokerid(log_dir)
    set_flag('confluent_ksql.storage.logs.attached')
    # Stop Kafka; removing the kafka.started state will trigger
    # a reconfigure if/when it's ready
    remove_state('confluent_ksql.configured')
    set_flag('confluent_ksql.force-reconfigure')


@hook('logs-storage-detaching')
def storage_detaching():
    unitdata.kv().unset('confluent_ksql.storage.log_dir')

    Ksql().stop()

    log('log storage detatched, reconfiguring to use temporary storage')

    remove_state('confluent_ksql.configured')
    set_flag('confluent_ksql.force-reconfigure')

    remove_state('confluent_ksql.started')
    remove_state('confluent_ksql.storage.logs.attached')
