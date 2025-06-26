from rest_framework import serializers
from .models import PasswordEntry

class PasswordEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordEntry
        fields = ['service', 'username', 'encryption_type', 'notes', 'tags']