from django.urls import path

from . import views

urlpatterns = [
    path('client/login',views.login,name='login'),
    path('client/movies',views.list,name='list'),
    path('generate_password/<str:password>',views.makepassword,name='makepassword')
]
