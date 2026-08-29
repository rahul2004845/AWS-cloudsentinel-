import os
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.getenv("MONGO_DB", "cloudsentinel")

client = None
db = None
logs_collection = None
alerts_collection = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client[MONGO_DB]
    logs_collection = db["logs"]
    alerts_collection = db["alerts"]
    print("MongoDB connected successfully")
except PyMongoError as e:
    print(f"MongoDB connection failed: {e}")