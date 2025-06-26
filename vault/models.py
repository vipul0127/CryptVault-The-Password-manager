from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class PasswordEntry(models.Model):
    ENCRYPTION_CHOICES = [
        ('AES', 'AES (Symmetric)'),
        ('RSA', 'RSA (Asymmetric)'),
        ('FERNET', 'Fernet (Symmetric)'),
        ('XOR', 'XOR Cipher (Simple)'),
        ('CAESAR', 'Caesar Cipher (Simple)'),
    ]
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_entries')
    service = models.CharField(max_length=150)
    username = models.CharField(max_length=150)
    encrypted_password = models.TextField()
    encryption_type = models.CharField(max_length=10, choices=ENCRYPTION_CHOICES)
    notes = models.TextField(blank=True, null=True)
    tags = models.CharField(max_length=300, blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.service} ({self.username})"

class AuditLog(models.Model):
    performed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=300)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.timestamp} - {self.performed_by.username} - {self.action}"

class StegImage(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    entry = models.ForeignKey(PasswordEntry, on_delete=models.CASCADE, related_name='steg_images')
    image = models.ImageField(upload_to='steganography_images')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"StegImage for {self.entry.service}"
    
    from django.db import models




import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class UserToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return timezone.now() > self.expires_at

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=2)  # token valid for 2 hours
        super().save(*args, **kwargs)