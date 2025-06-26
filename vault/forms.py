from django import forms
from django.contrib.auth.models import User
from .models import PasswordEntry, StegImage
from django.contrib.auth.password_validation import validate_password

class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput, strip=False)
    password2 = forms.CharField(label="Confirm Password", widget=forms.PasswordInput, strip=False)

    class Meta:
        model = User
        fields = ['username', 'email']  # email optional if you want

    def clean_password2(self):
        pw1 = self.cleaned_data.get('password1')
        pw2 = self.cleaned_data.get('password2')
        if pw1 and pw2 and pw1 != pw2:
            raise forms.ValidationError("Passwords don't match")
        validate_password(pw1)  # optional strong password validation
        return pw2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    username = forms.CharField(max_length=150)
    master_password = forms.CharField(widget=forms.PasswordInput)

# Define encryption type choices (excluding Caesar cipher)
ENCRYPTION_TYPE_CHOICES = [
    ('AES', 'AES'),
    # Add other secure encryption types if needed
]
from django import forms
from .models import PasswordEntry

class PasswordEntryForm(forms.ModelForm):
    plaintext_password = forms.CharField(
        widget=forms.PasswordInput,
        min_length=8,
        label="Password"
    )
    master_password = forms.CharField(
        widget=forms.PasswordInput,
        label="Master Password"
    )

    class Meta:
        model = PasswordEntry
        fields = ['service', 'username', 'plaintext_password', 'master_password', 'notes', 'encryption_type']
        widgets = {
            'notes': forms.Textarea(attrs={'rows': 3}),
            'encryption_type': forms.Select(choices=[
                ('AES', 'AES'),
                ('FERNET', 'Fernet'),
                ('RSA', 'RSA'),
                ('XOR', 'XOR'),
                ('CAESAR', 'Caesar'),
            ]),
        }
        
class StegImageUploadForm(forms.ModelForm):
    class Meta:
        model = StegImage
        fields = ['image']