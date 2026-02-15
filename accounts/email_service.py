import logging
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

logger = logging.getLogger(__name__)

def send_html_email(subject: str, to_email: str, text: str, html: str) -> None:
    msg = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[to_email],
    )
    msg.attach_alternative(html, "text/html")

    sent = msg.send(fail_silently=False)

    logger.info(
        "EMAIL_DEBUG sent=%s backend=%s host=%s port=%s from=%s to=%s user=%s",
        sent,
        getattr(settings, "EMAIL_BACKEND", None),
        getattr(settings, "EMAIL_HOST", None),
        getattr(settings, "EMAIL_PORT", None),
        getattr(settings, "DEFAULT_FROM_EMAIL", None),
        to_email,
        getattr(settings, "EMAIL_HOST_USER", None),
    )
