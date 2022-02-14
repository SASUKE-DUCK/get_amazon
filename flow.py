import logging, subprocess, re, base64, requests, sys, argparse, json
from pywidevine.cdm import cdm, deviceconfig

class WvDecrypt(object):
    WV_SYSTEM_ID = [
     237, 239, 139, 169, 121, 214, 74, 206, 163, 200, 39, 220, 213, 29, 33, 237]

    def __init__(self, init_data_b64, cert_data_b64):
        self.init_data_b64 = init_data_b64
        self.cert_data_b64 = cert_data_b64
        self.cdm = cdm.Cdm()

        def check_pssh(pssh_b64):
            pssh = base64.b64decode(pssh_b64)
            if not pssh[12:28] == bytes(self.WV_SYSTEM_ID):
                new_pssh = bytearray([0, 0, 0])
                new_pssh.append(32 + len(pssh))
                new_pssh[4:] = bytearray(b'pssh')
                new_pssh[8:] = [0, 0, 0, 0]
                new_pssh[13:] = self.WV_SYSTEM_ID
                new_pssh[29:] = [0, 0, 0, 0]
                new_pssh[31] = len(pssh)
                new_pssh[32:] = pssh
                return base64.b64encode(new_pssh)
            else:
                return pssh_b64

        self.session = self.cdm.open_session(check_pssh(self.init_data_b64), deviceconfig.DeviceConfig(deviceconfig.device_space_l3))
        if self.cert_data_b64:
            self.cdm.set_service_certificate(self.session, self.cert_data_b64)

    def log_message(self, msg):
        return ('{}').format(msg)

    def start_process(self):
        keyswvdecrypt = []
        try:
            for key in self.cdm.get_keys(self.session):
                if key.type == 'CONTENT':
                    keyswvdecrypt.append(self.log_message('{}:{}'.format(key.kid.hex(),key.key.hex())))

        except Exception:
            return (
             False, keyswvdecrypt)

        return (
         True, keyswvdecrypt)

    def get_challenge(self):
        return self.cdm.get_license_request(self.session)

    def update_license(self, license_b64):
        self.cdm.provide_license(self.session, license_b64)
        return True

parser = argparse.ArgumentParser(description="""
    Set pssh box header and license URL to return keys. 
    """)
parser.add_argument("--pssh", help="pssh box header in base64")
parser.add_argument("--license_url", help="Widevine License URL")
args = parser.parse_args()

# FInput = "000006c0.m4s"
FInput = "0000a4a8.m4s"
FOutput = "audiodec.mp4"
#### KID = "16662055CCD4402ABF79A4CD5693701F"
# KID = "c9271ddb096e4be68d41a2071ab26cae"
#15F600E3-BEA8-4814-9AC4-08D68E4EDC7D
#KID = "C7FC0AC4-9FBD-4FC8-A3CE-50ACAB4E08E8"
KID = "15F600E3-BEA8-4814-9AC4-08D68E4EDC7D"
#####################################################################KID = "81b524c0-9d6b-4741-b48d-19dc4ec3c736"
#####################################################################PSSH = 'AAAAOXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAABkIARIQx/wKxJ+9T8ijzlCsq04I6CIDU1BZ'
#PSSH = 'AAAAaHBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAEgIARIQFfYA476oSBSaxAjWjk7cfRoPdmVyaW1hdHJpeGNsYXJvIhpyPVNQT0dXU0hEX0RBU0hfQ0Umcz0yMzIwNioFU0RfSEQ='
PSSH = args.pssh
# drmToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1ZDMzNTBiMC1mMTFkLTNkZTQtYTA4OC0xMmJmN2YwMDAwMDEiLCJhdWQiOiJzcG9ydHNuZXRsaXZlIiwiaXNzIjoibm93LnNwb3J0c25ldC5jYSIsImVpZCI6IjdCMUY1NEQxLTFEMjQtNDMxRC1BMUJGLTA0NUJCNDU3NTY0QSIsImFpZCI6Imxpb24tMy1Sb2dlcnMwNWZkNzRiOTNkOGJiZjczOTg1NmNmNWNmMGViYjEyMiIsImRpZCI6IndlYi1FRTAzQ0EyMzEyNkYwODhBNTFFMjRDNTE3OUZDNERBQSIsInBsYyI6ZmFsc2UsImRlZiI6ImhkIiwiaWF0IjoxNTc4MzUwNDI1LCJleHAiOjE1NzgzNTA3MjUsImlzcyI6Im5vdy5zcG9ydHNuZXQuY2EifQ.aH4GLaSJqbqjd-1wTAPs5_Ghrtlhv9nuUsv962aRDQk'
# PSSH = "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxLZXlPU0F1dGhlbnRpY2F0aW9uWE1MPjxEYXRhPjxXaWRldmluZVBvbGljeSBmbF9DYW5QZXJzaXN0PSJmYWxzZSIgZmxfQ2FuUGxheT0idHJ1ZSI+PExpY2Vuc2VEdXJhdGlvbj4xNDQwMDwvTGljZW5zZUR1cmF0aW9uPjwvV2lkZXZpbmVQb2xpY3k+PFdpZGV2aW5lQ29udGVudEtleVNwZWMgVHJhY2tUeXBlPSJIRCI+PFNlY3VyaXR5TGV2ZWw+MTwvU2VjdXJpdHlMZXZlbD48L1dpZGV2aW5lQ29udGVudEtleVNwZWM+PExpY2Vuc2UgdHlwZT0ic2ltcGxlIj48UG9saWN5PjxJZD5lYzc4NmU4ZS1hM2RiLTIxMmItYzMwOC1iNWZiMzkxNDdkZjQ8L0lkPjwvUG9saWN5PjwvTGljZW5zZT48UG9saWN5IGlkPSJlYzc4NmU4ZS1hM2RiLTIxMmItYzMwOC1iNWZiMzkxNDdkZjQiIHBlcnNpc3RlbnQ9InRydWUiPjxFeHBpcmF0aW9uRGF0ZT4yMDIwLTAxLTA2IDIyOjE0OjQ2LjAwMDwvRXhwaXJhdGlvbkRhdGU+PC9Qb2xpY3k+PEtleUlETGlzdD48S2V5SUQ+OGE1NzMwMTgtZWZmNC00OTI0LTgzNWEtNDk3NDE5ODlhM2I3PC9LZXlJRD48L0tleUlETGlzdD48R2VuZXJhdGlvblRpbWU+MjAyMC0wMS0wNiAxODoxNDo0Ni4wMDA8L0dlbmVyYXRpb25UaW1lPjxFeHBpcmF0aW9uVGltZT4yMDIwLTAxLTA2IDIyOjE0OjQ2LjAwMDwvRXhwaXJhdGlvblRpbWU+PFVuaXF1ZUlkPjA2NmEzODhjMzdhNzI2YTc2MjRmMmQ2ZTA1NWJlYmZkPC9VbmlxdWVJZD48UlNBUHViS2V5SWQ+NDg3OGNiMDZlOTRkYmRlYzg5ZDFiYWZlMjZhZmE1NjA8L1JTQVB1YktleUlkPjwvRGF0YT48U2lnbmF0dXJlPlhyeWJkYml0QXdCUklzSEMrajlNeTdsUVIxeGxCbE5FbWhWVk9qN0ZYUTdjV0xYM0d0cGo0L3VpT2pPQXFDbU52ZTVXdmtNbE1pNVJOMFFuY3l0WGw2U2tkampVYlZxZW8ydEZhSkVZd0pFd3l2ZUFkR3A3K1Q0ZUgxVmd4ZlAzUWhpR3ppZElKckNzQXpheUJKRk43V2xPYXFBVTFGeVAzY2hXODYybzRnRURIMVRNNWhUV3Fma1BsRElDWlp3d2dyMWZibHRqay9QbmlwbGVkN3ROQWNTOGd1cTVtcTM5MjJIT0JUVXJHa21yNC9hSkZ2bWRjNks2SldqUXBSUldpTUg2T0ZxUGwxQ0h3UThqRFg4anV5dlhkQ09nblEwelFQcE9uT0V5bzhmaFNwOWRnekoyZDl1THp5NUc0ai9tRUszS1Y0Y3ROcElpb0dvSGlnci9oQT09PC9TaWduYXR1cmU+PC9LZXlPU0F1dGhlbnRpY2F0aW9uWE1MPgo="
# PSSH = "AAAAXXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAD0IARIgYzkyNzFkZGIwOTZlNGJlNjhkNDFhMjA3MWFiMjZjYWUaB3NsaW5ndHYiB05GTEhEMTAqBVNEX0hE"
# PSSH = "0801122063323236393339386533636634393464393738383030356564613435653538611a07736c696e67747622064655534548442a0553445f4844"
#### PSSH = "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIgMTY2NjIwNTVjY2Q0NDAyYWJmNzlhNGNkNTY5MzcwMWYaB3NsaW5ndHYiBUFFU1RSKgVTRF9IRA=="
#keys = ['eb676abbcb345e96bbcf616630f1a3da:100b6c20940f779a4589152b57d2dacb', '0294b9599d755de2bbf0fdca3fa5eab7:3bda2f40344c7def614227b9c0f03e26', '639da80cf23b55f3b8cab3f64cfa5df6:229f5f29b643e203004b30c4eaf348f4']
cert_request = b''
# cert_requesr = b//
# cert_request = b''
# cert_request = '{"env":"production","user_id":"5c9300b6-3481-11e8-b2c1-121d4d98adaa","channel_id":"fba55399460f4a7b8d3d436793dc0f90","message":[8,4]}'
# certurl = "https://widevine-proxy.appspot.com/proxy"
# licurl = "https://widevine-proxy.appspot.com/proxy"
#certurl = "https://tech.livehls.net/nowonline/multirights/widevine?deviceId=MzczNWUxMzMtNjI3ZC00ZTJiLWFlOTUtMDgzZTY1MGEyM2M1"
certurl = args.license_url
#licurl = "https://tech.livehls.net/nowonline/multirights/widevine?deviceId=MzczNWUxMzMtNjI3ZC00ZTJiLWFlOTUtMDgzZTY1MGEyM2M1"
licurl = args.license_url
headers = {
'dt-custom-data' : 'eyJ1c2VySWQiOiJzODM0NDczMTgyIiwic2Vzc2lvbklkIjoiNWYxYjNmZGMxZWJjNDEyOTQ0M2NkZTY4IiwibWVyY2hhbnQiOiJub3MifQ==',
'pragma': 'no-cache',
'cache-control': 'no-cache',
#'origin': 'https://tv.sfr.fr',
#'Origin': 'https://www.proximus.be',
'Origin': 'https://nostv.pt',
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36',
'dnt': '1',
#'deviceid': '5f62f098c4e617e0f9549f6518e190ef',
'accept': '*/*',
'sec-fetch-site': 'cross-site',
'sec-fetch-mode': 'cors',
'Referer': 'https://nostv.pt/',
#'Referer': 'https://www.proximus.be/pickx/fr/television/en-direct',
#'referer': 'https://tv.sfr.fr/channel/1',
'accept-encoding': 'gzip, deflate, br',
'accept-language': 'en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7,es;q=0.6,la;q=0.5',
    # 'x-authentication': 'U_ZGAE6U_ArvLe5hNzwfWU60YjXnw4flrNeiH1q7MPZtsIRx8ai6awp7fEde-ZQPZfJH7rlLiA7IGYNWEFIe09lVaP1fMBTeRCVpA74IBOVCYPE8LfXHuBzemGOfLXndvj9Pj-kcaCvSCkBNobZuQqMeoOYePJMRXjBctrk3JlcbpfUqfuVGP8m4fcIrAbJl_fr3488WxQLQGp7FFVdrBqzOxNlZ4on8GyxXvs5Bx7EMt11-e7A8IAFnGym6p-YmWhklJ91SGLfImZ77qA9d9RUlVsCS-TtDNED13Q7EiAeDjUVLUm7A',
    # 'Referer': 'https://www.tntgo.tv/',
    # 'Sec-Fetch-Mode': 'cors',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
    #'X-Forwarded-For': '20.40.16.0'
}
#proxies = {
#  'http': '',
#  'https': '201.20.106.142:8080',
#}

if not PSSH or not KID:
    PSSH, KID = getPSSH_KID(FInput, PSSH, KID)

#print(PSSH)
#print(KID)

print("Getting cert...")
#resp = requests.post(url=certurl, data=cert_request, headers=headers, proxies=proxies)
#resp = requests.post(url=certurl, data=cert_request)
#resp.status_code
#cert_decoded = resp.content
CERTIFICATE = None
#CERTIFICATE = base64.b64encode(cert_decoded)
#print(CERTIFICATE)

#print('Cert: ' + CERTIFICATE.decode('utf-8'))

print('PSSH IS: ' + PSSH)
print('Before wvdecrypt')
wvdecrypt = WvDecrypt(PSSH, CERTIFICATE)
print('After wvdecrypt')
print('Before chal')
chal = wvdecrypt.get_challenge()
print('Before chal')
print("Sending POST request to license url...")
print('CHALLENGE BIN: ' + str(chal))
print('CHALLENGE: ' + str(base64.b64encode(chal)))
resp = requests.post(url=licurl, data=chal, headers=headers)
license_decoded = resp.content
#json_parser = json.loads(license_decoded)
print('\n', license_decoded, '\n')
license_b64 = base64.b64encode(license_decoded)
#license_b64 = json_parser['license']

print('License: ' + license_b64.decode('utf-8'))
#print('License: ' + license_b64)

wvdecrypt.update_license(license_b64)
#wvdecrypt.update_license(license_decoded)
status, keys = wvdecrypt.start_process()
print(keys)
