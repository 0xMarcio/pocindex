from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import update_cves


class ProductNamesTests(unittest.TestCase):
    def products(self, affected):
        record = {
            "cveMetadata": {"state": "PUBLISHED"},
            "containers": {"cna": {
                "descriptions": [{"lang": "en", "value": "A vulnerability"}],
                "affected": affected,
            }},
        }
        return update_cves.details_from_record(record).products

    def test_package_only_affected_entries_keep_the_searchable_name(self):
        self.assertEqual(self.products([
            {"packageName": "xz", "defaultStatus": "unaffected",
             "versions": [{"version": "5.6.0", "status": "affected"}]},
            {"packageName": "OpenSSH", "defaultStatus": "affected"},
        ]), ["xz", "OpenSSH"])

    def test_unknown_product_falls_back_without_replacing_specific_products(self):
        self.assertEqual(self.products([
            {"product": "n/a", "packageName": "@vendor/widget"},
            {"product": "unknown", "packageName": "widget"},
            {"product": "Widget Server", "packageName": "widget-server"},
            {"product": "n/a", "packageName": "unknown"},
        ]), ["@vendor/widget", "widget", "Widget Server"])

    def test_unaffected_packages_remain_excluded(self):
        self.assertEqual(self.products([
            {"packageName": "safe-package", "defaultStatus": "unaffected"},
        ]), [])


if __name__ == "__main__":
    unittest.main()
