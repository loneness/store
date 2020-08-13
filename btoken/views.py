import hashlib
import json

from django.http import JsonResponse
from django.shortcuts import render

# Create your views here.
from tools import make_token
from user.models import UserProfile


def tokens(request):

    #{"username":"guoxiaonao","password":"123456","carts":null}
    json_str = request.body
    json_obj = json.loads(json_str)
    username = json_obj['username']
    password = json_obj['password']

    #参数检查

    #获取用户
    try:
        user = UserProfile.objects.get(username=username)
    except Exception as e:
        print('--get user error is')
        print(e)
        result = {'code':10200, 'error': 'The username or password is wrong'}
        return JsonResponse(result)

    m = hashlib.md5()
    m.update(password.encode())
    if m.hexdigest() != user.password:
        result = {'code': 10201, 'error': 'The username or password is wrong'}
        return JsonResponse(result)
    if user.is_active != True:
        result = {'code': 10202, 'error': '该用户尚未激活'}
        return JsonResponse(result)
    #签发token
    token = make_token(username)
    result = {'code':200, 'username':username, 'data':{'token':token.decode()}, 'carts_count':0}
    return JsonResponse(result)


