import time

import jwt
from django.conf import settings
import base64

from django.http import JsonResponse

from user.models import UserProfile
from django.core.cache import caches


def make_token(username, exp=3600 * 24):
    now = time.time()
    payload = {'username': username, 'exp': int(now + exp)}
    key = settings.JWT_TOKEN_KEY

    return jwt.encode(payload, key, algorithm='HS256')


def login_check(func):
    def wrapper(self, request, *args, **kwargs):
        token = request.META.get('HTTP_AUTHORIZATION')
        if not token:
            result = {'code': 403, 'error': 'Please login'}
            return JsonResponse(result)
        try:
            res = jwt.decode(token, settings.JWT_TOKEN_KEY, algorithms='HS256')
        except Exception as e:
            print('jwt decode error is %s' % (e))
            result = {'code': 403, 'error': 'Please login'}
            return JsonResponse(result)
        username = res['username']
        user = UserProfile.objects.get(username=username)
        request.myuser = user
        return func(self, request, *args, **kwargs)

    return wrapper


from django.db import models


class BaseModel(models.Model):
    created_time = models.DateTimeField(auto_now_add=True)
    updated_time = models.DateTimeField(auto_now=True)

    class Meta:
        # 指定当前模型类为抽象模型类
        # 特点：1，该模型类不会有对应的表；2，其他模型类可继承该类，继承后，当前字段一并被继承
        abstract = True


from django.core.cache import caches


# @cache_check(key_prefix='gd', key_param='sku_id', cache='goods_detail',expire=30)
def cache_check(**cache_kwargs):
    def _cache_check(func):
        def wrapper(self, request, *args, **kwargs):
            CACHE = caches['default']
            if 'cache' in cache_kwargs:
                CACHE = caches[cache_kwargs['cache']]
            key_prefix = cache_kwargs['key_prefix']
            key_param = cache_kwargs['key_param']
            expire = cache_kwargs.get('expire', 30)
            if key_param not in kwargs:
                raise ('sku id is wrong')
            cache_key = key_prefix + str(kwargs[key_param])
            res = CACHE.get(cache_key)
            if res:
                return res
            res = func(self, request, *args, **kwargs)
            CACHE.set(cache_key, res, expire)
            return res

        return wrapper

    return _cache_check

# def cache_check(**cache_kwagrs):
#     def _cache_check(func):
#         def wrapper(self, request, *args, **kwargs):
#             #获取存储位置
#             CACHE = caches['default']
#             if 'cache' in cache_kwagrs:
#                 CACHE = caches[cache_kwagrs['cache']]
#             key_prefix = cache_kwagrs['key_prefix']
#             key_param = cache_kwagrs['key_param']
#             expire = cache_kwagrs.get('expire', 30)
#
#             if key_param not in kwargs:
#                 raise
#             cache_key = key_prefix + str(kwargs[key_param])
#             print('cache key is %s'%(cache_key))
#             #检查缓存
#             res = CACHE.get(cache_key)
#             if res:
#                 print('return %s cache'%(cache_key))
#                 return res
#             #没有缓存
#             res = func(self, request, *args, **kwargs)
#             CACHE.set(cache_key, res, expire)
#             return res
#         return wrapper
#     return _cache_check