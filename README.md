# The Reel Ones - Sprint Foundation

This project provides the required sprint foundation:

- SQLite database for user management.
- Auth routes for account creation and login.
- JWT returned on successful register/login.
- Password salting/hashing using bcrypt.
- Front-end pages for login, registration, and internal app sections.
- Internal pages enforce JWT presence and redirect to login if missing.
- Protected backend routes requiring JWT validation.
- Front-end dashboard invokes protected routes with JWT bearer token.

## Run locally

```bash
npm install
npm start
```

Open: <http://localhost:3000/login.html>
