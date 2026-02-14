from django.conf import settings
from django.core.mail import EmailMultiAlternatives

def send_html_email(subject: str, to_email: str, text: str, html: str) -> None:
    msg = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[to_email],
    )
    msg.attach_alternative(html, "text/html")
    msg.send(fail_silently=False)
