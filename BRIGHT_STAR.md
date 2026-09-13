# 🌟 Bright Star — Run Memory

<!-- BRIGHT_STAR_DATA — generated; do not edit -->
```json
{
  "version": 1,
  "generatedAt": "2026-09-13T16:35:47.786Z",
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
    "authObjectId": "kyDp5F6iKSmaaYqudJie1S",
    "protectedResource": {
      "method": "GET",
      "url": "/rest/wallet/balance"
    }
  },
  "hints": {
    "startup": [
      "Built and ran the repo's Dockerfile successfully with `docker run -d --name juice-shop-ci -p 3000:3000 juice-shop-ci`. The app serves on port 3000 and responds 200 at `/`. No extra boot env vars were required for local startup."
    ]
  }
}
```
<!-- BRIGHT_STAR_DATA -->
