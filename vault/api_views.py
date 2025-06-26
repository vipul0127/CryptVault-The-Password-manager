import json
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from .models import PasswordEntry
from .serializers import PasswordEntrySerializer

@csrf_exempt  # Optional: you can replace with proper CSRF handling if used securely
@login_required
def password_search_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "POST method required."}, status=405)
    
    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    q = data.get('q', '').strip()
    master_password = data.get('master_password', '')

    if not q:
        return JsonResponse({"error": "Field 'q' is required."}, status=400)
    if not master_password:
        return JsonResponse({"error": "Field 'master_password' is required."}, status=400)

    user = request.user
    user_auth = authenticate(username=user.username, password=master_password)
    if user_auth is None:
        return JsonResponse({"error": "Invalid master password."}, status=403)

    entries = PasswordEntry.objects.filter(owner=user, service__icontains=q)[:10]

    serializer = PasswordEntrySerializer(entries, many=True)
    return JsonResponse({"results": serializer.data})