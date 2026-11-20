#!/usr/bin/env python3
"""
NetShield Automated MongoDB Backup & Disaster Recovery Verification Script
Supports timestamped JSON export backup and full database restore verification.
"""

import os
import sys
import json
import argparse
from datetime import datetime
from urllib.parse import quote_plus
from pymongo import MongoClient

DEFAULT_MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017/netshield_db")
BACKUP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backups"))

COLLECTIONS_TO_BACKUP = ["logs", "alerts", "users", "settings", "systemmetrics", "operationalincidents"]

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle PyMongo BSON types like ObjectId and datetime."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return {"$date": obj.isoformat()}
        if hasattr(obj, "__str__"):
            return str(obj)
        return super().default(obj)

def parse_json_object(obj):
    """Decodes custom JSON representations back to MongoDB compatible types."""
    if isinstance(obj, dict):
        if "$date" in obj:
            return datetime.fromisoformat(obj["$date"])
        return {k: parse_json_object(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [parse_json_object(item) for item in obj]
    return obj

def perform_backup(mongo_uri, backup_dir=None):
    """Executes full database backup for all NetShield collections."""
    if not backup_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = os.path.join(BACKUP_ROOT, f"netshield_backup_{timestamp}")

    os.makedirs(backup_dir, exist_ok=True)
    print(f"[BACKUP] Connecting to MongoDB: {mongo_uri}")
    client = MongoClient(mongo_uri)

    default_db = client.get_default_database()
    db_name = default_db.name if default_db is not None else "netshield_db"
    db = client[db_name]

    manifest = {
        "timestamp": datetime.now().isoformat(),
        "database": db_name,
        "collections": {}
    }

    for col_name in COLLECTIONS_TO_BACKUP:
        collection = db[col_name]
        docs = list(collection.find({}))
        col_file = os.path.join(backup_dir, f"{col_name}.json")

        with open(col_file, "w", encoding="utf-8") as f:
            json.dump(docs, f, cls=CustomJSONEncoder, indent=2)

        manifest["collections"][col_name] = len(docs)
        print(f"  -> Exported {len(docs)} documents from '{col_name}' to {os.path.basename(col_file)}")

    manifest_file = os.path.join(backup_dir, "manifest.json")
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"[BACKUP SUCCESS] Backup completed successfully in: {backup_dir}")
    return backup_dir, manifest

def perform_restore(mongo_uri, backup_dir, target_db_name=None):
    """Restores database collections from a timestamped backup directory."""
    manifest_file = os.path.join(backup_dir, "manifest.json")
    if not os.path.exists(manifest_file):
        raise FileNotFoundError(f"Invalid backup directory: Missing manifest.json in {backup_dir}")

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    print(f"[RESTORE] Connecting to MongoDB: {mongo_uri}")
    client = MongoClient(mongo_uri)
    db_name = target_db_name or manifest.get("database", "netshield_db")
    db = client[db_name]

    print(f"[RESTORE] Restoring into target database: '{db_name}'...")
    restored_counts = {}

    for col_name, expected_count in manifest.get("collections", {}).items():
        col_file = os.path.join(backup_dir, f"{col_name}.json")
        if not os.path.exists(col_file):
            print(f"  -> Warning: Collection file {col_file} missing. Skipping.")
            continue

        with open(col_file, "r", encoding="utf-8") as f:
            docs = json.load(f, object_hook=parse_json_object)

        # Clear target collection
        db[col_name].delete_many({})

        if docs:
            db[col_name].insert_many(docs)

        actual_count = db[col_name].count_documents({})
        restored_counts[col_name] = actual_count
        print(f"  -> Restored '{col_name}': {actual_count}/{expected_count} documents.")
        assert actual_count == expected_count, f"Mismatch in {col_name}: Expected {expected_count}, got {actual_count}"

    print(f"[RESTORE SUCCESS] Database '{db_name}' restored successfully from {backup_dir}")
    return restored_counts

def main():
    parser = argparse.ArgumentParser(description="NetShield Automated MongoDB Backup & Disaster Recovery Tool")
    parser.add_argument("--action", choices=["backup", "restore"], default="backup", help="Action to perform")
    parser.add_argument("--uri", default=DEFAULT_MONGO_URI, help="MongoDB connection URI")
    parser.add_argument("--backup-dir", default=None, help="Directory for backup/restore")
    parser.add_argument("--target-db", default=None, help="Target database name for restore")

    args = parser.parse_args()

    if args.action == "backup":
        perform_backup(args.uri, args.backup_dir)
    elif args.action == "restore":
        if not args.backup_dir:
            # Find latest backup in backups/
            if not os.path.exists(BACKUP_ROOT) or not os.listdir(BACKUP_ROOT):
                print("[ERROR] No backups found in backups/ directory.")
                sys.exit(1)
            backups = sorted([os.path.join(BACKUP_ROOT, d) for d in os.listdir(BACKUP_ROOT) if os.path.isdir(os.path.join(BACKUP_ROOT, d))])
            args.backup_dir = backups[-1]
            print(f"[RESTORE] Using latest backup directory: {args.backup_dir}")
        perform_restore(args.uri, args.backup_dir, args.target_db)

if __name__ == "__main__":
    main()
