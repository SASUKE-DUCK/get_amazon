import logging, subprocess, re, base64, requests, sys, argparse
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


cert_request = b'\x08\x04'
PSSH = args.pssh
certurl = args.license_url
licurl = args.license_url


#print(PSSH)

#print("Getting cert...")
#resp = requests.post(url=certurl, data=cert_request)
#resp.status_code
#cert_decoded = resp.content
#CERTIFICATE = base64.b64encode(cert_decoded)
CERTIFICATE = None
#print(CERTIFICATE)

#print('Cert: ' + CERTIFICATE.decode('utf-8'))

#print('PSSH IS: ' + PSSH)
#print('Before wvdecrypt')
wvdecrypt = WvDecrypt(PSSH, CERTIFICATE)
#print('After wvdecrypt')
#print('Before chal')
chal = wvdecrypt.get_challenge()
print(base64.b64encode(chal))
#print('Before chal')
#print("Sending POST request to license url...")
resp = requests.post(url=licurl, data=chal)
license_decoded = resp.content
print('\n', license_decoded, '\n')
license_b64 = base64.b64encode(license_decoded) 

print('License: ' + license_b64.decode('utf-8'))

wvdecrypt.update_license(license_b64)
status, keys = wvdecrypt.start_process()
#print(status)
print(keys)
