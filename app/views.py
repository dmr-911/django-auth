from django.http import HttpResponse


def Mizan(request):
    print(request)
    return HttpResponse("Hello there")
