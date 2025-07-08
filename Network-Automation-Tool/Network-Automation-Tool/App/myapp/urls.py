from django.urls import path  # Import path function from django.urls
from .views import home, home_check, firewall,firewall_update,fw_firewall,zones,resolve_fqdn_to_ip,fetch_all_apps,Add,Firewall_names,App,check_object, create_object , check_object_name  # Import views from current app
 
# Define urlpatterns for routing URLs to views
urlpatterns = [
    path('home/', home, name='home'),  # Route 'home/' URL to home view function, named 'home'
    path('home_check/', home_check, name='home_check'),  # Route 'home_check/' URL to home_check view function, named 'home_check'
    path('firewall/', firewall, name='firewall'),
    path("firewall_fetch/",firewall_update,name="firewall_fetch"),
    path("firewall_search/",fw_firewall,name="firewall_search"),
    path("zones/",zones,name="zones"),
    path("apps/",fetch_all_apps,name="fetch_all_apps"),
    path("fqdn/",resolve_fqdn_to_ip,name="fqdn"),
    path("Add/",Add,name="add"),
    path("Firewall_name/",Firewall_names,name="Firewall_name"),
    path("App/",App,name="app"),
    # Object Checker URLs
    path('check_object/', check_object, name='check_object'),
    path('create_object/', create_object, name='create_object'),
    path('check_object_name/', check_object_name, name='check_object_name'),  # New endpoint
    
    # path('download/', download, name='download'),  # Route 'download/' URL to download view function, named 'download'

]