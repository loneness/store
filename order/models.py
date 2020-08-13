from django.db import models

# Create your models here.


from goods.models import SKU
from tools import BaseModel
from user.models import UserProfile


STATUS_CHOICES = (

    (1, "待付款"),
    (2, "待发货"),
    (3, "待收货"),
    (4, "订单完成")
)


class OrderInfo(BaseModel):

    order_id=models.CharField(max_length=64,primary_key=True,verbose_name='订单号')
    user_profile=models.ForeignKey(UserProfile,on_delete=models.CASCADE)
    total_amount=models.DecimalField(max_digits=10,decimal_places=2,verbose_name='商品总金额')
    total_count=models.IntegerField(verbose_name='商品总数')
    pay_method=models.SmallIntegerField(default=1,verbose_name='支付方式')
    freight=models.DecimalField(max_digits=10,decimal_places=2,verbose_name='运费')
    status = models.SmallIntegerField(verbose_name="订单状态", choices=STATUS_CHOICES)

    # 订单地址
    receiver = models.CharField(verbose_name="收件人", max_length=10)
    address = models.CharField(max_length=100, verbose_name="收货地址")
    receiver_mobile = models.CharField(max_length=11)
    tag = models.CharField(verbose_name="标签", max_length=10)

    class Meta:
        db_table = "order_order_info"


class OrderGoods(BaseModel):
    order_info = models.ForeignKey(OrderInfo, on_delete=models.CASCADE)
    sku = models.ForeignKey(SKU, on_delete=models.CASCADE)
    count = models.IntegerField(default=1, verbose_name="数量")
    price = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='单价')

    class Meta:
        db_table = "order_order_goods"