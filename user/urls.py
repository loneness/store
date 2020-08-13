from django.urls import path, include

from user import views

urlpatterns = [

    path('activation',views.activation),
    path('<str:username>/address/<str:id>',views.AddressView.as_view()),
    path('weibo/authorization',views.weibo_url_view),
    path('weibo/users', views.WeiboUserView.as_view())

]


# App Key：366740855
# App Secret：cb8dba281aa6b54e9818baa8faf15915
# https://api.weibo.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI
