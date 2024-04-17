from django.core.cache import cache
from blocklist.models import BlackIps
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .settings import ADMIN_IPS

class DDOSMiddleware(MiddlewareMixin):

    def init(self, get_response):
        self.get_response = get_response

    def call(self, request):
        # So'rov jo'natish tezligini o'rnating (daqiqasiga so'rovlar soni)
        rate_limit_threshold = 100

        # So'rovning IP manzilini oling
        ip_address = request.META.get('REMOTE_ADDR')
        print("ip address: ", ip_address)
        # IP-manzil qora ro'yxatga kiritilganligini tekshiring
        ip_address_obj, created = BlackIps.objects.get_or_create(ip=ip_address)
        if not created and ip_address_obj.blocked and ip_address not in ADMIN_IPS:
            return HttpResponseForbidden("IP manzilingiz shubhali faoliyat tufayli bloklandi.")

        # IP manzili uchun so'rovlar sonini oshiring
        ip_address_obj.reason = "DDOS attack"
        ip_address_obj.request_count += 1
        ip_address_obj.save(update_fields=['request_count'])

        # Tarif chegarasi chegarasidan oshib ketganligini tekshiring
        if ip_address_obj.request_count > rate_limit_threshold and ip_address not in ADMIN_IPS:
            # IP-manzilni qora ro'yxatga qo'shing
            # IP address 5 soatga bloklangandi
            ip_address_obj.blocked = True
            ip_address_obj.save()
            return HttpResponseForbidden("Haddan tashqari so'rovlar tufayli IP-manzilingiz bloklandi")
        response = self.get_response(request)
        return response

    def process_request(self, request):
        return self.call(request)
