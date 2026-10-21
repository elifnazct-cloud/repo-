# Beavizor

Beauty services and appointment platform.

## Deployment status

**Not deployed.** The application source archive has not yet been committed to this repository. Do not connect a public production deployment until source files are uploaded, reviewed and tested.

## Required before production

- Upload reviewed project source files, excluding `.env`, database files, passwords and tokens.
- Configure Ruby dependencies (`webrick`, `sqlite3`) and production startup.
- Configure persistent database storage, SMTP email verification, and strong administrator credentials in hosting environment variables.
- Test signup, login, password reset, booking, access controls and backups.
- Connect `beavizor.com` DNS after successful staging deployment.

The repository is public. Never commit secrets or real user data.
