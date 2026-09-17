# 🌟 Bright Star — Run Memory

<!-- BRIGHT_STAR_DATA — generated; do not edit -->
```json
{
  "version": 1,
  "generatedAt": "2026-09-17T16:26:21.874Z",
  "techStack": {
    "languages": [
      "JavaScript",
      "TypeScript"
    ],
    "frameworks": [
      "Express"
    ],
    "databases": [
      "SQL (Sequelize)",
      "SQLite"
    ]
  },
  "startup": {
    "command": "docker run -d --name juice-shop-ci -p 3000:3000 juice-shop-ci",
    "port": 3000,
    "prerequisites": [],
    "envVars": {}
  },
  "setup": {
    "completed": true,
    "credentials": {
      "username": "bright_test",
      "password": "BrightTest123!",
      "email": "bright@test.com"
    }
  },
  "auth": {
    "hasAuth": true,
    "authObjectId": "wozFc3ZkPzWvrEASW84Z6e",
    "protectedResource": {
      "method": "GET",
      "url": "/rest/wallet/balance"
    }
  },
  "hints": {
    "startup": [
      "Built the repo-owned Dockerfile with `docker build -t juice-shop-ci .` and ran it with `docker run -d --name juice-shop-ci -p 3000:3000 juice-shop-ci`. The app serves on port 3000; `http://127.0.0.1:3000/` returns 200. First boot took about 2 minutes before `Server listening on port 3000` appeared in logs."
    ]
  }
}
```
<!-- BRIGHT_STAR_DATA -->
