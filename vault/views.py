import base64
import secrets
from vault.utils import decrypt_steg_password
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse

from .forms import RegistrationForm, LoginForm, PasswordEntryForm, StegImageUploadForm
from .models import PasswordEntry, AuditLog, StegImage
from .encryption import *
from .utils import estimate_crack_time, caesar_rotator

from django.conf import settings

# Registration (first user only)
def register(request):
    if settings.DEBUG:  # Allow registration only if no users exist or DEBUG for dev.
        from django.contrib.auth.models import User
        if User.objects.exists():
            return redirect('login')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            mp = form.cleaned_data['master_password']
            user = User.objects.create_user(username=username, password=mp)
            messages.success(request, 'User created. Please login.')
            return redirect('login')
    else:
        form = RegistrationForm()
    return render(request, 'vault/register.html', {'form':form})

# Login
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages

def user_login(request):
    # Get the single registered user (assuming single-user app)
    try:
        user = User.objects.first()
    except User.DoesNotExist:
        # If no user exists, redirect to registration or welcome
        return redirect('welcome')

    if request.method == 'POST':
        password = request.POST.get('master_password')

        # Authenticate using known username + submitted password
        user = authenticate(request, username=user.username, password=password)
        if user is not None:
            login(request, user)
            return redirect('vault_home')
        else:
            messages.error(request, "Incorrect master password. Please try again.")

    # GET request, show login page with username prefilled and read-only
    return render(request, 'vault/login.html', {
        'username': user.username,  # prefill username in template
    })
@login_required
def user_logout(request):
    AuditLog.objects.create(performed_by=request.user, action="User logged out")
    logout(request)
    return redirect('login')

from django.contrib.auth.decorators import login_required
# vault/views.py

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Q

# Import your PasswordEntry model here
from .models import PasswordEntry

# Placeholder decryption function for normal passwords (replace with your logic)
def decrypt_password(entry, user):
    # Implement actual decryption here
    return entry.password  # Replace with real decrypted password

# Placeholder steg decryption function (implement your steg extraction and decryption logic)
def decrypt_steg_password(steg_image, user):
    # Implement actual steg password extraction and decryption here
    return "[decrypted_steg_password]"
@login_required
def vault_home(request):
    user = request.user
    q = request.GET.get('q', '')
    enc_filter = request.GET.get('encryption_type', '')
    entries = PasswordEntry.objects.filter(owner=user)
    if q:
        entries = entries.filter(Q(service__icontains=q) | Q(notes__icontains=q))
    if enc_filter:
        entries = entries.filter(encryption_type=enc_filter)
    encryption_types = [
        ('AES', 'AES'),
        ('FERNET', 'Fernet'),
        ('RSA', 'RSA'),
        ('XOR', 'XOR'),
        ('CAESAR', 'Caesar')
    ]
    decrypted_passwords = {}
    for entry in entries:
        decrypted_passwords[entry.id] = '[Enter master password]'
    context = {
        'entries': entries,
        'q': q,
        'enc_filter': enc_filter,
        'encryption_types': encryption_types,
        'decrypted_passwords': decrypted_passwords,
        'decrypted_steg_passwords': {}
    }
    return render(request, 'vault/vault_home.html', context)



@login_required
def vault_add(request):
    if request.method == 'POST':
        form = PasswordEntryForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=False)
            entry.owner = request.user
            plaintext_password = form.cleaned_data['plaintext_password']
            master_password = form.cleaned_data['master_password']
            
            # Verify the master password
            user = authenticate(username=request.user.username, password=master_password)
            if not user:
                messages.error(request, 'Invalid master password')
                return render(request, 'vault/vault_form.html', {'form': form})

            enc_type = entry.encryption_type or 'AES'
            try:
                encrypted_password = encrypt_entry_password(plaintext_password, master_password, enc_type, request.POST)
                entry.encrypted_password = encrypted_password
                entry.save()
                AuditLog.objects.create(performed_by=request.user, action=f"Added password entry {entry.service}")
                messages.success(request, 'Entry added')
                return redirect('vault_home')
            except Exception as e:
                messages.error(request, f'Encryption failed: {str(e)}')
                return render(request, 'vault/vault_form.html', {'form': form})
    else:
        form = PasswordEntryForm()
    return render(request, 'vault/vault_form.html', {'form': form})



@login_required
def vault_edit(request, pk):
    entry = get_object_or_404(PasswordEntry, pk=pk, owner=request.user)
    if request.method == 'POST':
        form = PasswordEntryForm(request.POST, instance=entry)
        if form.is_valid():
            plaintext_password = form.cleaned_data['plaintext_password']
            master_password = form.cleaned_data['master_password']
            
            # Verify the master password
            user = authenticate(username=request.user.username, password=master_password)
            if not user:
                messages.error(request, 'Invalid master password')
                return render(request, 'vault/vault_form.html', {'form': form, 'editing': True})

            if plaintext_password:
                enc_type = form.cleaned_data['encryption_type'] or 'AES'
                try:
                    entry.encrypted_password = encrypt_entry_password(plaintext_password, master_password, enc_type, request.POST)
                except Exception as e:
                    messages.error(request, f'Encryption failed: {str(e)}')
                    return render(request, 'vault/vault_form.html', {'form': form, 'editing': True})
            form.save()
            AuditLog.objects.create(performed_by=request.user, action=f"Updated password entry {entry.service}")
            messages.success(request, 'Entry updated')
            return redirect('vault_home')
    else:
        form = PasswordEntryForm(instance=entry)
    try:
        decrypted_pw = decrypt_entry_password(entry.encrypted_password, request.POST.get('master_password', ''), entry.encryption_type, {})
    except Exception:
        decrypted_pw = ''
    return render(request, 'vault/vault_form.html', {'form': form, 'editing': True, 'plaintext_password': decrypted_pw})


@login_required
def vault_delete(request, pk):
    entry = get_object_or_404(PasswordEntry, pk=pk, owner=request.user)
    if request.method == 'POST':
        AuditLog.objects.create(performed_by=request.user, action=f"Deleted password entry {entry.service}")
        entry.delete()
        messages.success(request, 'Entry deleted')
        return redirect('vault_home')
    return render(request, 'vault/vault_confirm_delete.html', {'entry': entry})

# Encryption helper wrappers
def encrypt_entry_password(plaintext, master_password, enc_type, post_data):
    if enc_type == 'AES':
        key = derive_key(master_password)
        return aes_encrypt(plaintext, key)
    elif enc_type == 'FERNET':
        key = fernet_key_from_password(master_password)
        return fernet_encrypt(plaintext, key)
    elif enc_type == 'RSA':
        private_key, public_key = generate_rsa_keypair()
        return rsa_encrypt(plaintext, public_key)
    elif enc_type == 'XOR':
        key = master_password[:8] or 'defaultkey'
        return xor_encrypt(plaintext, key)
    elif enc_type == 'CAESAR':
        shift = int(post_data.get('caesar_shift', 3))
        return caesar_encrypt(plaintext, shift)
    else:
        return "[Unknown encryption]"
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from .views import derive_key

from .encryption import aes_encrypt, fernet_encrypt, rsa_encrypt, xor_encrypt, caesar_encrypt, derive_key, fernet_key_from_password, generate_rsa_keypair

def encrypt_entry_password(plaintext, master_password, enc_type, post_data=None):
    post_data = post_data or {}
    if enc_type == 'AES':
        key = derive_key(master_password)
        return aes_encrypt(plaintext, key)
    elif enc_type == 'FERNET':
        key = fernet_key_from_password(master_password)
        return fernet_encrypt(plaintext, key)
    elif enc_type == 'RSA':
        private_key, public_key = generate_rsa_keypair()
        return rsa_encrypt(plaintext, public_key)
    elif enc_type == 'XOR':
        key = master_password[:8] or 'defaultkey'
        return xor_encrypt(plaintext, key)
    elif enc_type == 'CAESAR':
        shift = int(post_data.get('caesar_shift', 3))
        return caesar_encrypt(plaintext, shift)
    else:
        return "[Unknown encryption]"


def generate_strong_password(length=16):
    import string
    import secrets
    alphabets = string.ascii_letters + string.digits + string.punctuation
    # remove problematic chars
    alphabets = alphabets.replace("'", "").replace('"', '').replace('\\', '')
    return ''.join(secrets.choice(alphabets) for _ in range(length))

# API for password strength meter
@login_required
def password_strength_api(request):
    password = request.GET.get('password', '')
    score = 0
    feedback = []
    import string

    if len(password) >= 8:
        score += 1
    else:
        feedback.append('Password too short.')

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append('Add lowercase letters.')

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append('Add uppercase letters.')

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append('Add digits.')

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append('Add special characters.')

    score = min(score, 4)
    return JsonResponse({'score': score, 'feedback': feedback})

# Encryption Demo (AES and RSA)
@login_required
def encryption_demo(request):
    demo_result = None
    if request.method == 'POST':
        text = request.POST.get('plaintext')
        algo = request.POST.get('algorithm')
        if not text:
            messages.error(request, 'Enter text to encrypt')
        else:
            if algo == 'AES':
                key = derive_key("demo_password")
                iv, ct = aes_demo_encrypt(text, key)
                demo_result = {'algorithm':'AES','iv':iv,'ciphertext':ct}
            elif algo == 'RSA':
                priv, pub = generate_rsa_keypair()
                enc = rsa_encrypt(text, pub)
                dec = rsa_decrypt(enc, priv)
                demo_result = {'algorithm':'RSA','private_key': priv.decode(),'public_key': pub.decode(),'ciphertext': enc,'plaintext_decrypted': dec}
            else:
                messages.error(request, 'Unknown algorithm selected')

    return render(request, 'vault/encryption_demo.html', {'demo_result': demo_result})

# Password Cracker Simulator
@login_required
def password_cracker_simulator(request):
    time_estimate = None
    if 'password' in request.GET:
        pw = request.GET.get('password','')
        time_estimate = estimate_crack_time(pw)
    return render(request, 'vault/password_cracker.html', {'time_estimate': time_estimate})

# Password Strength Game (simple guessing game)
@login_required
def password_strength_game(request):
    game_result = None
    if request.method == 'POST':
        guess = request.POST.get('guess')
        correct = request.session.get('game_password')
        if not correct:
            messages.error(request, 'Start a new game.')
        else:
            if guess == correct:
                game_result = 'Correct! Strong passwords are hard to guess!'
            else:
                game_result = 'Wrong guess. Keep trying!'
    else:
        # Generate random password to guess
        pw = generate_strong_password(6)
        request.session['game_password'] = pw

    return render(request, 'vault/password_strength_game.html', {'game_password': request.session.get('game_password'), 'game_result': game_result})

# Steganography password storage
@login_required
def steg_image_upload(request, entry_id):
    entry = get_object_or_404(PasswordEntry, id=entry_id, owner=request.user)
    if request.method == 'POST':
        form = StegImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            steg_img = form.save(commit=False)
            steg_img.owner = request.user
            steg_img.entry = entry
            steg_img.save()
            messages.success(request, 'Image uploaded for steganography storage.')
            return redirect('vault_home')
    else:
        form = StegImageUploadForm()
    return render(request, 'vault/steg_upload.html', {'form': form, 'entry': entry})

@login_required
def invisible_ink_toggle(request):
    # Just toggle a session flag
    current = request.session.get('invisible_ink', False)
    request.session['invisible_ink'] = not current
    messages.info(request, f'Invisible Ink mode {"enabled" if not current else "disabled"}')
    return redirect('vault_home')

@login_required
def educational_labels(request):
    # Simple page explaining ciphers
    ciphers = [
        {'name':'AES (Advanced Encryption Standard)', 'desc':'AES is a symmetric encryption algorithm...'},
        {'name':'RSA', 'desc':'RSA is an asymmetric encryption algorithm...'},
        {'name':'Fernet', 'desc':'Fernet is symmetric with message integrity...'},
        {'name':'XOR Cipher', 'desc':'XOR is a simple symmetric cipher...'},
        {'name':'Caesar Cipher', 'desc':'Classic rotational cipher shifting letters...'},
    ]
    return render(request, 'vault/educational_labels.html', {'ciphers':ciphers})

@login_required
def caesar_rotator_view(request):
    result = None
    if request.method == 'POST':
        text = request.POST.get('text','')
        try:
            shift = int(request.POST.get('shift',3))
        except:
            shift = 3
        if text:
            result = caesar_rotator(text, shift)
    return render(request, 'vault/caesar_rotator.html', {'result':result})

# Minimal browser add-on integration page
@login_required
def browser_addon_info(request):
    return render(request, 'vault/browser_addon.html')


@login_required
def steg_image_list(request, entry_id):
    entry = get_object_or_404(PasswordEntry, id=entry_id, owner=request.user)
    images = entry.steg_images.all()
    return render(request, 'vault/steg_image_list.html', {'entry': entry, 'images': images})




from django.contrib.auth import login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import RegistrationForm  # your user registration form (see example below)

def register_first_user(request):
    # Check if any user exists
    if User.objects.exists():
        # If users exist, redirect to login page
        return redirect('login')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()  # save the user instance
            login(request, user)  # automatically login the new user
            messages.success(request, "Welcome! Registration successful. Please remember your credentials securely.")
            return redirect('vault_home')  # redirect after registration
    else:
        form = RegistrationForm()

    return render(request, 'vault/register_first_user.html', {
        'form': form,
    })

from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.shortcuts import redirect

def index_redirect(request):
    if not User.objects.exists():
        # No users yet — redirect to welcome page as first step
        return redirect('welcome')
    
    # Users exist — check if user is authenticated
    if not request.user.is_authenticated:
        # Not logged in — redirect to login page
        return redirect('login')
    else:
        # Authenticated — redirect to vault home/dashboard
        return redirect('vault_home')





from django.shortcuts import render, redirect
from django.contrib.auth.models import User

def welcome(request):
    # If user registered, redirect to login
  
    return render(request, 'vault/welcome.html')




import json
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserToken, PasswordEntry
from .serializers import PasswordEntrySerializer
from django.contrib.auth.models import User
import secrets
from functools import wraps

# Custom decorator to check token auth
def token_auth_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Token '):
            return JsonResponse({'error': 'Authorization token required'}, status=401)
        token = auth_header[6:]
        try:
            token_obj = UserToken.objects.get(token=token)
            if token_obj.is_expired():
                return JsonResponse({'error': 'Token expired'}, status=401)
            request.user = token_obj.user
        except UserToken.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped_view

from django.views.decorators.csrf import csrf_exempt
import json
import secrets
from django.http import JsonResponse
from django.contrib.auth import authenticate
from .models import UserToken
from django.utils import timezone
from datetime import timedelta

@csrf_exempt
def api_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)
    try:
        data = json.loads(request.body)
        username = data.get('username')
        master_password = data.get('master_password')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not username or not master_password:
        return JsonResponse({'error': 'Username and master_password required'}, status=400)

    user = authenticate(username=username, password=master_password)
    if not user:
        return JsonResponse({'error': 'Invalid credentials'}, status=403)

    token_obj, created = UserToken.objects.get_or_create(user=user)
    if not created and token_obj.is_expired():
        token_obj.token = secrets.token_hex(32)
        token_obj.expires_at = timezone.now() + timedelta(hours=2)
        token_obj.save()

    return JsonResponse({'token': token_obj.token})

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import PasswordEntry
from django.contrib.auth import authenticate
import json

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import PasswordEntry
from django.contrib.auth import authenticate
import json

@csrf_exempt
@token_auth_required
def password_search_api(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)
    try:
        data = json.loads(request.body)
        query = data.get('q', '')
        master_password = data.get('master_password')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    if not master_password:
        return JsonResponse({'error': 'Master password required'}, status=400)

    user = authenticate(username=request.user.username, password=master_password)
    if not user:
        return JsonResponse({'error': 'Invalid master password'}, status=403)

    entries = PasswordEntry.objects.filter(
        owner=user,
        service__icontains=query
    ).values('id', 'service', 'username')

    results = [
        {
            'id': entry['id'],
            'service': entry['service'],
            'username': entry['username']
        }
        for entry in entries
    ]

    return JsonResponse({'results': results})









#dgfhgsvfdgfhgfghssgfhjh,vmchghdfds



from django.http import FileResponse
from django.shortcuts import render
import os
import zipfile
from io import BytesIO

import os
import zipfile
from django.http import HttpResponse
from django.conf import settings

def download_extension(request):
    # Use packaged path
    extension_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'chrome_extension')
    zip_path = os.path.join(settings.BASE_DIR, 'cryptvault_extension.zip')
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(extension_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, extension_dir)
                zipf.write(file_path, os.path.join('cryptvault_extension', arcname))
    
    with open(zip_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/zip')
        response['Content-Disposition'] = 'attachment; filename=cryptvault_extension.zip'
        return response
    
def get_username(request):
    user = User.objects.first()
    if user:
        return JsonResponse({'username': user.username})
    return JsonResponse({'error': 'No user found'}, status=404)

from django.http import JsonResponse
from django.contrib.auth import authenticate
from .models import PasswordEntry

from django.http import JsonResponse
from django.contrib.auth import authenticate
from .models import PasswordEntry
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib.auth import authenticate
from .models import PasswordEntry
from .encryption import decrypt_entry_password
from django.contrib.auth.decorators import login_required
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_password(request, entry_id):
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Token '):
        token = auth_header[6:]
        try:
            token_obj = UserToken.objects.get(token=token)
            if token_obj.is_expired():
                return JsonResponse({'error': 'Token expired'}, status=401)
            request.user = token_obj.user
        except UserToken.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=401)

    master_password = request.GET.get('master_password')
    if not master_password:
        return JsonResponse({'error': 'Master password required'}, status=400)

    try:
        entry = PasswordEntry.objects.get(id=entry_id, owner=request.user)
        decrypted_password = decrypt_entry_password(
            entry.encrypted_password,
            master_password,
            entry.encryption_type,
            {}
        )
        return JsonResponse({
            'username': entry.username,
            'password': decrypted_password
        })
    except PasswordEntry.DoesNotExist:
        return JsonResponse({'error': 'Entry not found'}, status=404)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        return JsonResponse({'error': f'Decryption failed: {str(e)}'}, status=500)
        
@login_required
def vault_search(request):
    q = request.GET.get('q', '')
    entries = PasswordEntry.objects.filter(owner=request.user, service__icontains=q)[:10]
    context = {'q': q, 'entries': entries}
    return render(request, 'vault/vault_search.html', context)


from django.http import JsonResponse

def health_check(request):
    return JsonResponse({'status': 'ok'})


def extension_guide(request):

    return render(request, 'vault/extension_guide.html')


def privacy(request):

    return render(request, 'vault/privacy.html')

def share(request):

    return render(request, 'vault/share.html')