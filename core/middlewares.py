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
        if cache.get(f'ddos:blacklist:{ip_address}') or BlackIps.objects.filter(ip=ip_address, is_active=True).exists():
            return HttpResponseForbidden("IP manzilingiz shubhali faoliyat tufayli bloklandi.")

        # IP manzili uchun so'rovlar sonini oshiring
        request_count = cache.get(f'ddos:request_count:{ip_address}', 0)
        request_count += 1
        cache.set(f'ddos:request_count:{ip_address}', request_count, timeout=30)
        # Tarif chegarasi chegarasidan oshib ketganligini tekshiring
        if request_count > rate_limit_threshold:
            # IP-manzilni qora ro'yxatga qo'shing
            cache.set(f'ddos:blacklist:{ip_address}', True, timeout=60)  # IP address 5 soatga bloklangandi
            BlackIps.objects.create(ip=ip_address, reason='DDOS')
            return HttpResponseForbidden("Haddan tashqari so'rovlar tufayli IP-manzilingiz bloklandi")
        response = self.get_response(request)
        return response

    def process_request(self, request):
        return self.call(request)
