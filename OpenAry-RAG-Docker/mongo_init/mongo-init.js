db.createUser({
  user: "genai",
  pwd: "openary",
  roles: [
    { role: "readWrite", db: "genai_svc_dev" },
    { role: "readWrite", db: "llm_chat_history" },
    { role: "userAdminAnyDatabase", db: "admin" },
    { role: "dbAdminAnyDatabase", db: "admin" }
  ],
  mechanisms: ["SCRAM-SHA-1"]
});

db = db.getSiblingDB('genai_svc_dev');
db.createCollection('init');

db = db.getSiblingDB('llm_chat_history');
db.createCollection('init');