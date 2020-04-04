# Create your views here.
#IMPORT models
from .models import Movie,ApiUsers

#IMPORT LIBRARIRES/FUNCTIONS
#from django.shortcuts import render , HttpResponse
from django.http import JsonResponse
import json
from firstapp.customClasses import *
#IMPORT DJANGO PASSWORD HASH GENERATOR AND COMPARE
from django.contrib.auth.hashers import make_password, check_password

#check_password(noHashPassword,HashedPassword) this funcion validate if the password match to the hash

def login(request):

    #VALIDATE METHOD
    if request.method == 'POST':
        #DECLARE RESPONSE
        response_data = {}

        #CHECK JSON STRUCTURE
        if checkJson().isJson(request.body)==True:
        #CHECK JSON CONTENT
            data=json.loads(request.body)
            attr_error = FalseattrErrorMsg = ""
            #CHECK IF USER EXITST
            if 'user' not in data:
                attr_error = True
                attrErrorMsg = "User is required"
            elif 'password' not in data:
                attr_error = True
                attrErrorMsg = "Password is required"

            if attr_error == True:
                response_data['result'] = 'error'
                response_data['message'] = attrErrorMsg
                return JsonResponse(response_data, status=401)
            #TAKE PASSWORD OF THE USER
            try:
                nombre = data['user']
                user = ApiUsers.objects.get(user=nombre)
            except ApiUsers.DoesNotExist:
                response_data['result'] = 'error'
                response_data['message'] = 'The user does not exist or the password is incorrect'
                return JsonResponse(response_data, status=401)

            #CHECK IF PASSWORD IS CORRECT
            psw = data['password']
            hash = user.password

            if check_password(psw, hash)==False:
                response_data['result'] = 'error'
                response_data['message'] = 'The user does not exist or the password is incorrect'
                return JsonResponse(response_data, status=401)

            #CHECK IF USER HAS API-KEY
            if user.api_key == None:
                #obj.api_key = newApiKey
                #obj.save()
                user.api_key = ApiKey().generate_key_complex()
                user.save()

            response_data['result'] = 'success'
            response_data['message'] = 'Logged in'
            response_data['api key'] = user.api_key
            return JsonResponse(response_data, status=200)
        else:
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid JSON'
            return JsonResponse(response_data, status=400)

    #RETURN RESPONSE
    else:
        response_data = {}
        response_data['result'] = 'error'
        response_data['message'] = 'Invalid Request'
        return JsonResponse(response_data, status=400)

def list(request):

        #VALIDATE METHOD
        if request.method == 'POST':
            #DECLARE RESPONSE
            response_data = {}
            response_data['movies'] = {}
            #CHECK JSON STRUCTURE
            if checkJson().isJson(request.body)==True:
            #CHECK JSON CONTENT
                data=json.loads(request.body)
                try:
                    nombre = data['user']
                    user = ApiUsers.objects.get(user=nombre)
                except ApiUsers.DoesNotExist:
                    response_data['result'] = 'error'
                    response_data['message'] = 'The user does not exist or the password is incorrect'
                    return JsonResponse(response_data, status=401)

                #CHECK IF PASSWORD IS CORRECT
                psw = data['password']
                hash = user.password

                if check_password(psw, hash)==False:
                    response_data['result'] = 'error'
                    response_data['message'] = 'The user does not exist or the password is incorrect'
                    return JsonResponse(response_data, status=401)

                #CHECK IF USER HAS API-KEY
                if ApiKey().check(request):
                    if request.headers["user-api-key"]==user.api_key:
                        count = 0
                        for i in Movie.objects.all():
                            response_data['movies'][count] = {}
                            response_data['movies'][count]['id'] = i.movieid
                            response_data['movies'][count]['title'] = i.movietitle
                            response_data['movies'][count]['releaseDate'] = i.releasedate
                            response_data['movies'][count]['imageUrl'] = i.imageurl
                            response_data['movies'][count]['description'] = i.description
                            count = count + 1
                        response_data['result'] = 'success'
                        return JsonResponse(response_data, status=200)
                    else:
                        response_data['result'] = 'error'
                        response_data['message'] = 'Invalid Api-key'
                        return JsonResponse(response_data, status=401)



                response_data['result'] = 'success'
                response_data['message'] = 'Logged in'
                response_data['api key'] = user.api_key
                return JsonResponse(response_data, status=200)
            else:
                response_data['result'] = 'error'
                response_data['message'] = 'Invalid JSON'
                return JsonResponse(response_data, status=400)

        #RETURN RESPONSE
        else:
            response_data = {}
            response_data['result'] = 'error'
            response_data['message'] = 'Invalid Request'
            return JsonResponse(response_data, status=400)


def makepassword(request,password):
    hashPassword = make_password(password)
    response_data = {}
    response_data['password'] = hashPassword
    return JsonResponse(response_data, status=200)
