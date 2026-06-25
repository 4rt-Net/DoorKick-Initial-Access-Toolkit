#!/usr/bin/env python3
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.base_module import BaseModule
from utils.colors import *


class MongoDBNoAuthModule(BaseModule):
    """MongoDB No Authentication Checker"""

    def __init__(self, frontdoor):
        super().__init__(frontdoor)
        self.name = "MongoDB No Auth"
        self.port = 27017

    def run(self):
        """Validate whether MongoDB allows unauthenticated database access."""
        module_name = "MongoDB No Auth"
        target = self.get_target()

        print(f"\n[*] Testing {target}:27017 for MongoDB...")

        if not self.check_port(27017, timeout=3):
            self.log(module_name, "ERROR", "Port 27017 closed")
            return

        try:
            from pymongo import MongoClient
            from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
        except ImportError:
            self.log(module_name, "ERROR", "pymongo is not installed; cannot validate MongoDB authorization")
            self.log(module_name, "INFO", "Install dependency: pip install pymongo")
            return

        uri = f"mongodb://{target}:27017/?serverSelectionTimeoutMS=4000"
        client = MongoClient(uri)

        try:
            client.admin.command("ping")
            self.log(module_name, "POTENTIAL", "MongoDB responded to ping")

            dbs = client.admin.command("listDatabases")
            db_names = [db.get("name", "unknown") for db in dbs.get("databases", [])]
            self.report_validation(module_name, "Unauthenticated listDatabases", True, "database enumeration succeeded")
            if db_names:
                self.log(module_name, "INFO", f"Databases visible without auth: {', '.join(db_names[:10])}")
            self.log(module_name, "RCE_POSSIBLE", "Unauthenticated administrative access may enable data theft and privilege abuse")

        except OperationFailure as e:
            message = str(e).lower()
            if "not authorized" in message or "requires authentication" in message:
                self.report_validation(module_name, "Unauthenticated listDatabases", False, "access denied by authentication controls")
            else:
                self.log(module_name, "ERROR", f"MongoDB operation failed: {str(e)}")
        except ServerSelectionTimeoutError as e:
            self.log(module_name, "ERROR", f"MongoDB server selection timeout: {str(e)}")
        except Exception as e:
            self.log(module_name, "ERROR", f"MongoDB validation error: {str(e)}")
        finally:
            client.close()