from django.core.cache import cache
from blocklist.models import BlackIps
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin


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
        ip_address_obj = BlackIps.objects.get(ip=ip_address, is_active=True)
        if ip_address_obj:
            return HttpResponseForbidden("IP manzilingiz shubhali faoliyat tufayli bloklandi.")

        # IP manzili uchun so'rovlar sonini oshiring
        new_ip_address = BlackIps.objects.create(ip=ip_address, reason='DDOS')
        new_ip_address.request_count += 1
        new_ip_address.save(update_fields=['request_count'])

        # Tarif chegarasi chegarasidan oshib ketganligini tekshiring
        if ip_address.request_count > rate_limit_threshold:
            # IP-manzilni qora ro'yxatga qo'shing
            # IP address 5 soatga bloklangandi
            new_ip_address.blocked = True
            new_ip_address.save()
            return HttpResponseForbidden("Haddan tashqari so'rovlar tufayli IP-manzilingiz bloklandi")
        response = self.get_response(request)
        return response

    def process_request(self, request):
        return self.call(request)
