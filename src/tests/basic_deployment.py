#!/usr/bin/python3
"""
Ubuntu charm functional test using Zaza. Take note that the Ubuntu
charm does not have any relations or config options to exercise.
"""

import unittest
import zaza.model as model

class BasicDeployment(unittest.TestCase):
    def test_ksql_deployment(self):
        first_unit = model.get_units('confluent-ksql')[0]
        result = model.run_on_leader('ubuntu', 'lsb_release -cs')
        self.assertEqual(result['Code'], '0')
        self.assertEqual(result['Stdout'].strip(), first_unit.series)
