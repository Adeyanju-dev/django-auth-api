# Django Authentication API (Production Ready)

A fully-featured production-ready authentication system built with Django REST Framework.

Live API: https://django-auth-api-ttu7.onrender.com  
Swagger Docs: https://django-auth-api-ttu7.onrender.com/api/docs/

---

## Features

- User Registration
- Email Verification (token-based)
- Resend Verification Email
- JWT Authentication (Access & Refresh tokens)
- Login (verified users only)
- Forgot Password & Reset Password via Email
- Role-Based Access Control (Admin-only endpoints)
- Rate Limiting (brute-force protection)
- PostgreSQL Database
- Swagger / OpenAPI Documentation
- Secure Password Validation

---

## Tech Stack

- Python
- Django & Django REST Framework
- SimpleJWT (+ Token Blacklist)
- PostgreSQL
- Brevo SMTP (Transactional Email)
- Render (Deployment)

---

## Core Endpoints

Base URL: `/api/auth/`

| Method | Endpoint | Description |
|------|--------|------------|
| POST | `/register/` | Register new user + send verification email |
| GET | `/verify/<uidb64>/<token>/` | Verify email |
| POST | `/resend-verification/` | Resend verification email |
| POST | `/login/` | Login & receive JWT tokens |
| POST | `/forgot-password/` | Request password reset |
| POST | `/reset-password/<uidb64>/<token>/` | Set new password |
| POST | `/token/refresh/` | Refresh access token |
| GET | `/protected/` | Verified users only |
| GET | `/admin-only/` | Admin users only |

---

## Environment Variables

Create a `.env` file:

```env
SECRET_KEY=your_secret_key
DEBUG=False
ALLOWED_HOSTS=django-auth-api-ttu7.onrender.com,localhost,127.0.0.1

DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=your_db_host
DB_PORT=5432

PUBLIC_API_BASE_URL=https://django-auth-api-ttu7.onrender.com

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp-relay.brevo.com
EMAIL_PORT=2525
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your_brevo_smtp_login
EMAIL_HOST_PASSWORD=your_brevo_smtp_key
DEFAULT_FROM_EMAIL=Micheal Dev <ademivel8@gmail.com>
EMAIL_TIMEOUT=30


## Local Setup
git clone https://github.com/Adeyanju-dev/django-auth-api.git
cd django-auth-api
python -m venv .venv

# activate venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver


## Notes
- SMTP uses port 2525 to avoid common hosting restrictions.
- Password reset and resend verification endpoints return generic success responses to prevent email enumeration attacks.
- Built following production security best practices.


## Author
Micheal Adeyanju
GitHub: https://github.com/Adeyanju-dev