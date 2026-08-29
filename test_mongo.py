from pymongo import MongoClient

MONGO_URI = "mongodb+srv://cloud_security:cloud_security@cluster0.l30zegx.mongodb.net/?appName=Cluster0"
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
