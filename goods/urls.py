from django.urls import path
from django.views.decorators.cache import cache_page

from . import views

urlpatterns = [

    path('index/', cache_page(600,cache='goods')(views.GoodsIndexView.as_view())),
    path('detail/<int:sku_id>/', views.GoodsDetailView.as_view())

]