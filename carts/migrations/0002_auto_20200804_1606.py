# Generated by Django 2.2.12 on 2020-08-04 16:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('carts', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='orderinfo',
            name='user_profile',
        ),
        migrations.DeleteModel(
            name='OrderGoods',
        ),
        migrations.DeleteModel(
            name='OrderInfo',
        ),
    ]
