import base64
import hashlib
from urllib.parse import urlencode

import requests
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import render
import json

from django.core.mail import send_mail
from django.conf import settings
from django.views import View

from tools import make_token, login_check
# Create your views here.
from .models import UserProfile, WeiboProfile, Address
import random
from django.core.cache import cache


def users(request):

    if request.method == 'POST':
        json_str = request.body
        json_obj = json.loads(json_str)
        username = json_obj['uname']
        password = json_obj['password']
        phone = json_obj['phone']
        email = json_obj['email']

        user = UserProfile.objects.filter(username=username)
        if user:
            result = {'code': 10100, 'error': 'The username is already existed !'}
            return JsonResponse(result)

        m = hashlib.md5()
        m.update(password.encode())
        password_h = m.hexdigest()

        try:
            UserProfile.objects.create(username=username, password=password_h, phone=phone, email=email)
        except:
            result = {'code': 10101, 'error': 'The username is already existed !'}
            return JsonResponse(result)

        code = random.randint(1000, 9999)
        code_str = '%s_%s'%(code, username)
        b64_code = base64.urlsafe_b64encode(code_str.encode()).decode()
        print('email_active_%s' % (username))
        cache.set('email_active_%s'%(username), code, 3600 * 24 * 3)
        verify_url = 'http://127.0.0.1:7000/dadashop/templates/active.html?code=%s' % (b64_code)
        send_email(email, verify_url)

        token = make_token(username)
        return JsonResponse({'code':200,'username':username, 'data':{'token':token.decode()}, 'carts_count':0})



def send_email(email, verify_url):
    subject = '达达商城激活邮件'
    html_message = '''
    尊敬的用户您好，请点击激活链接进行激活,
    <a href="%s" target="_blank">点击此处</a>
    ''' % (verify_url)
    res = send_mail(subject, '', '2925930571@qq.com', [email], html_message=html_message)
    return res


def activation(request):
    code = request.GET.get('code')
    if not code:
        return JsonResponse({'code': 10102, 'error': 'not code'})

    str_code = base64.urlsafe_b64decode(code.encode()).decode()
    code = str_code.split('_')[0]

    username = str_code.split('_')[1]
    code_random = cache.get('email_active_%s'%(username))
    print(code_random)
    if not code_random:
        res = {'code': 10100, 'error': 'the code is wrong'}
        return JsonResponse(res)
    if int(code) != int(code_random):
        print(code,code_random)
        res = {'code': 10101, 'error': 'the code is wrong'}
        return JsonResponse(res)
    try:
        user = UserProfile.objects.get(username=username)
    except:
        res = {'code': 10102, 'error': 'the username is wrong'}
        return JsonResponse(res)
    user.is_active = True
    user.save()
    cache.delete('email_active_%s' % (username))
    res = {'code': 200,'data':'ok'}
    return JsonResponse(res)


def weibo_url_view(request):

    #https://api.weibo.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI
    weibo_url = 'https://api.weibo.com/oauth2/authorize'

    params = {
        'client_id': settings.WEIBO_APP_KEY,
        'response_type': 'code',
        'redirect_uri': settings.WEIBO_REDIRECT_URI
    }

    url = weibo_url + '?' + urlencode(params)

    return JsonResponse({'code':200, 'oauth_url':url})


class WeiboUserView(View):

    def get(self, request):

        code = request.GET.get('code')
        print(code)
        if not code:
            return JsonResponse({'code': 10106, 'error':'Please give me code'})

        token_url = 'https://api.weibo.com/oauth2/access_token'
        #发送Post请求

        req_data = {
            'client_id': settings.WEIBO_APP_KEY,
            'client_secret': settings.WEIBO_APP_SECRET,
            'grant_type': 'authorization_code',
            'redirect_uri': settings.WEIBO_REDIRECT_URI,
            'code': code
        }

        response = requests.post(token_url, data=req_data)
        if response.status_code==200:
            json_data=json.loads(response.text)
        else:
            print(response.status_code)
            return JsonResponse({'code': 10107, 'error': 'The weibo server is busy'})
        if json_data.get('error'):
            print(json_data['error'])
            return JsonResponse({'code': 10108, 'error': 'The weibo server is busy'})

        print('-----success get token----')
        print(json_data)

        weibo_uid=json_data['uid']
        access_token=json_data['access_token']

        try:
            weibo_user=WeiboProfile.objects.get(wuid=weibo_uid)
        except Exception as e:
            user=WeiboProfile.objects.create(access_token=access_token,wuid=weibo_uid)
            data = {
                'code': 201,
                'uid': weibo_uid
            }
            return JsonResponse(data)
        else:
            user=weibo_user.user_profile
            if user:
                # 之前绑定过 - 走正常登录流程
                username = user.username
                token = make_token(username)
                return JsonResponse({'code': 200, 'username': username, 'token': token.decode()})

            else:
                # 未绑定
                data = {
                    'code': 201,
                    'uid': weibo_uid
                }
                return JsonResponse(data)

    def post(self,request):
        json_str = request.body
        json_obj = json.loads(json_str)

        # {"uid":"1861495121","username":"guoxiao8","password":"123456","phone":"13488873110","email":"572708691@qq.com"}
        wuid = json_obj['uid']
        username = json_obj['username']
        password = json_obj['password']
        phone = json_obj['phone']
        email = json_obj['email']

        m = hashlib.md5()
        m.update(password.encode())
        try:
            with transaction.atomic():
                # 生成一个 UserProfile
                user = UserProfile.objects.create(username=username, password=m.hexdigest(), email=email, phone=phone)
                # update 给wuid对应的 WeiboProfile 对象 绑定 外键
                weibo_user = WeiboProfile.objects.get(wuid=wuid)
                weibo_user.user_profile = user
                weibo_user.save()
        except Exception as e:
            print('---bind weibouser error is %s' % (e))
            return JsonResponse({'code': 10109, 'error': 'The database is error'})

        token = make_token(username)
        return JsonResponse({'code': 200, 'username': username, 'token': token.decode()})


class AddressView(View):

    @login_check
    def get(self,request,username,id):
        all_address = Address.objects.filter(user_profile=request.myuser, is_active=True)

        address_list = []
        for addr in all_address:
            addr_data = {}
            addr_data['id'] = addr.id
            addr_data['address'] = addr.address
            addr_data['receiver'] = addr.receiver
            addr_data['receiver_mobile'] = addr.receiver_mobile
            addr_data['tag'] = addr.tag
            addr_data['postcode'] = addr.postcode
            addr_data['is_default'] = addr.is_default
            address_list.append(addr_data)

        return JsonResponse({'code': 200, 'addresslist': address_list})

    @login_check
    def post(self,request,username,id):
        json_str = request.body
        json_obj = json.loads(json_str)
        receiver = json_obj['receiver']
        receiver_phone = json_obj['receiver_phone']
        address = json_obj['address']
        postcode = json_obj['postcode']
        tag = json_obj['tag']

        user = request.myuser
        old_address = Address.objects.filter(user_profile=user, is_active=True)
        is_default = False
        if not old_address:
            is_default = True

        Address.objects.create(
            user_profile=user,
            receiver=receiver,
            address=address,
            receiver_mobile=receiver_phone,
            postcode=postcode,
            tag=tag,
            is_default=is_default
        )

        return JsonResponse({'code': 200, 'data': '新增地址成功！'})