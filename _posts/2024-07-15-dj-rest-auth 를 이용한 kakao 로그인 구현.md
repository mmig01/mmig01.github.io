---
title: dj-rest-auth 를 이용한 kakao 로그인 구현
categories: [backend, django]
tags: [django , django_restframework, python, django-allauth, dj-rest-auth, backend]
---

오늘은 django rest framework 에서 django-allauth 와 dj-rest-auth 를 이용한 카카오톡 로그인 구현 방법에 대해 포스팅 하겠습니다.

## Django REST framework

Django REST Framework(DRF)는 Django를 기반으로 한 웹 API 구축 도구입니다. DRF는 빠르게 웹 API를 개발할 수 있도록 다양한 기능과 모듈을 제공하여 백엔드 개발자들이 데이터 직렬화, 권한 부여, 인증, API 문서화 등을 간편하게 처리할 수 있도록 도와줍니다. 자세한 설명은 [ **여기서**](https://www.django-rest-framework.org/tutorial/1-serialization/) 확인하실 수 있습니다.



대부분은 [**해당 블로그**](https://medium.com/chanjongs-programming-diary/django-rest-framework%EB%A1%9C-%EC%86%8C%EC%85%9C-%EB%A1%9C%EA%B7%B8%EC%9D%B8-api-%EA%B5%AC%ED%98%84%ED%95%B4%EB%B3%B4%EA%B8%B0-google-kakao-github-2-cf1b4059b5d5)를 참고 하였습니다. 아주 상세히 설명 되어 있어서 참고하기 좋았습니다. 

몇 가지 다르게 설정한 부분이 있는데 이 부분은 아래에서 설명 하도록 하겠습니다.



## Django-allauth

Django Allauth는 Django 프로젝트에서 사용자 인증(authentication), 계정 관리(account management), 소셜 로그인(social login) 기능을 쉽게 구현할 수 있도록 돕는 통합 애플리케이션입니다. Allauth는 이메일 확인, 비밀번호 재설정, 소셜 계정 연동 등 다양한 기능을 기본적으로 지원합니다.



## Dj-rest-auth

dj-rest-auth는 Django 프로젝트에서 RESTful API를 통한 인증(authentication) 및 계정 관리(account management) 기능을 제공하는 라이브러리입니다. Django Allauth와 통합되어 작동할 수 있으며, Django REST Framework(DRF)와 함께 사용할 수 있습니다. 



## 프로그램 설치

```python
pip install djangorestframework
pip install djangorestframework-simplejwt
pip install dj-rest-auth
# 이 부분이 가장 중요!!! 꼭 이 버전으로 설치
pip install django-allauth==0.61.1
```

먼저 위 명령어를 입력하여 프로그램을 설치 해줍니다. 마지막에 서술 하겠지만 마지막 줄이 제 오류의 원인 이었습니다. 그래서 위 버전으로 설치를 해주셔야 정상적으로 실행이 됩니다.



## Urls.py

```python
# project/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('dj_rest_auth.urls')),
    path('accounts/', include('accounts.urls')),    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# accounts/urls.py
from django.urls import path
from accounts import views
app_name = "accounts"
urlpatterns = [
    path('', views.login, name='login'),
    path('kakao/login/', views.kakao_login, name='kakao_login'),
    path('kakao/login/callback/', views.kakao_callback, name='kakao_callback'),
    path('kakao/login/finish/', views.KakaoLogin.as_view(), name='kakao_login_todjango'),
]

```



## Models.py

```python
# accounts/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser, BaseUserManager


class UserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = None
    email = models.EmailField(unique=True, max_length=255)
    # 닉네임 필드 추가
    nickname = models.CharField(unique=True, max_length=30)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
```



## Views.py

```python
# accounts/views.py

import json
import requests
from django.shortcuts import redirect, render
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse
from json.decoder import JSONDecodeError
from rest_framework import status
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.kakao import views as kakao_view
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from allauth.socialaccount.models import SocialAccount
from .models import User

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

BASE_URL = 'http://localhost:8000/'
KAKAO_CALLBACK_URI = BASE_URL + 'accounts/kakao/login/callback/'

state = getattr(settings, 'STATE')

def login(request):
    return render(request, 'accounts/logintest.html')

    
def kakao_login(request):
    rest_api_key = getattr(settings, 'KAKAO_REST_API_KEY')
    return redirect(
        f"https://kauth.kakao.com/oauth/authorize?client_id={rest_api_key}&redirect_uri={KAKAO_CALLBACK_URI}&response_type=code&prompt=login"
    )


def kakao_callback(request):
    rest_api_key = getattr(settings, 'KAKAO_REST_API_KEY')
    code = request.GET.get("code")
    print("code : " , code)
    redirect_uri = KAKAO_CALLBACK_URI
    """
    Access Token Request
    """
    token_req = requests.get(
        f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={rest_api_key}&redirect_uri={redirect_uri}&code={code}")
    token_req_json = token_req.json()

    print("token JSON:", json.dumps(token_req_json, indent=4, ensure_ascii=False))
    error = token_req_json.get("error")
    if error is not None:
        raise JSONDecodeError(error)
    access_token = token_req_json.get("access_token")
    """
    Email Request
    """
    profile_request = requests.get(
        "https://kapi.kakao.com/v2/user/me", headers={"Authorization": f"Bearer {access_token}"})
    profile_json = profile_request.json()

    print("Profile JSON:", json.dumps(profile_json, indent=4, ensure_ascii=False))
    error = profile_json.get("error")
    if error is not None:
        raise JSONDecodeError(error)
    
    kakao_account = profile_json.get('kakao_account')
    # 사용자의 닉네임, 프로필 사진, 섬네일 사진
    properties = profile_json.get('properties')
    """
    kakao_account에서 이메일 외에
    카카오톡 프로필 이미지, 배경 이미지 url 가져올 수 있음
    print(kakao_account) 참고
    """
    # 필요한 정보를 가져옴
    email = kakao_account.get('email')
    # accounts 의 user db 에 입력할 nickname 선언
    nickname = properties.get('nickname')

    """
    Signup or Signin Request
    """
    try:
        user = User.objects.get(email=email)
        # 기존에 가입된 유저의 Provider가 kakao가 아니면 에러 발생, 맞으면 로그인
        # 다른 SNS로 가입된 유저
        social_user = SocialAccount.objects.get(user=user)
        if social_user is None:
            return JsonResponse({'err_msg': 'email exists but not social user'}, status=status.HTTP_400_BAD_REQUEST)
        if social_user.provider != 'kakao':
            return JsonResponse({'err_msg': 'no matching social type'}, status=status.HTTP_400_BAD_REQUEST)
        # 기존에 kakao로 가입된 유저
        data = {'access_token': access_token, 'code': code}
        accept = requests.post(
            f"{BASE_URL}accounts/kakao/login/finish/", data=data)
        accept_status = accept.status_code

        print("try 에서 출력한 status 값 : " , accept_status)

        if accept_status != 200:
            return JsonResponse({'err_msg': 'failed to signin'}, status=accept_status)
        accept_json = accept.json()
        
        userinfo = {
            "email" : user.email,
            "nickname" : user.nickname
        }
        accept_json.pop('user', None)
        accept_json['userinfo'] = userinfo
        
        return JsonResponse(accept_json)
        
    except User.DoesNotExist:
        # 기존에 가입된 유저가 없으면 새로 가입
        data = {'access_token': access_token, 'code': code}

        accept = requests.post(
            f"{BASE_URL}accounts/kakao/login/finish/", data=data)
        accept_status = accept.status_code
        print("except 에서 출력한 status 값 : " , accept_status)
        if accept_status != 200:
            return JsonResponse({'err_msg': 'failed to signup'}, status=accept_status)
        
        # 유저 닉네임을 카카오의 nickname 필드와 동일하게 변경
        user = User.objects.get(email=email)
        user.nickname = nickname
        user.save()
        # Access Token, Refresh token 
        accept_json = accept.json()
        userinfo = {
            "email" : user.email,
            "nickname" : user.nickname
        }
        accept_json.pop('user', None)
        accept_json['userinfo'] = userinfo
        return JsonResponse(accept_json)


class KakaoLogin(SocialLoginView):
    adapter_class = kakao_view.KakaoOAuth2Adapter
    client_class = OAuth2Client
    callback_url = KAKAO_CALLBACK_URI

```

Views.py 같은 경우 print 문을 추가하여 직접 상황을 확인할 수 있게 하였습니다.

## 프로그램 실행

![image](https://github.com/user-attachments/assets/217efc89-2d94-42b2-b82a-c6d7da0c4535)

위 블로그를 참고하여 세팅을 모두 끝냈다고 가정하고 해당 url 로 들어가면 아래와 같은 화면이 나옵니다.

![image](https://github.com/user-attachments/assets/b6a31aea-dafe-430f-9afe-efb530f6a1f2)

이제 본인 카카오 이메일과 비밀번호를 입력 해봅시다.

![image](https://github.com/user-attachments/assets/b49d5519-a2c5-43ac-aff3-0421b2d91cfd)

그러면 다음과 같은 jwt 토큰이 발급 됩니다. 본 테스트에서는 json request 에 userinfo 를 추가 하였습니다.

![image](https://github.com/user-attachments/assets/42c362fc-4eaf-4275-9993-ed03603cce83)

user data 가 새로 생성되어 accounts_user 에 저장되는 것을 확인 하였습니다. 

## 에러 발생

2024.07.14 기준 django-allauth 버전을 최신 버전으로 설치하면 처음으로 user 를 생성할 때 400 request 가 발생하였습니다.

## 해결책

해결책은 위에서 서술한 대로 django-allauth 버전을 다운 그레이드 하는 것입니다. 상황은 다르지만 [**이 곳**](https://stackoverflow.com/questions/78477908/dj-rest-auth-with-google-login-typeerror-oauth2provider-get-scope-takes-1-po) 을 참고 하여 해결하였습니다.

```python
pip install django-allauth==0.61.1
```

django-allauth 버전을 위 버전으로 다운 그레이드 하면 해결 됩니다.