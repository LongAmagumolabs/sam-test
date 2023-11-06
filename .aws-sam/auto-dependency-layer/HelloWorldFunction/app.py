import json
import io
import datetime
import textwrap
import os
import boto3
import fintech
import pytz
fintech.register()
from fintech.sepa import Account, SEPACreditTransfer
from fintech.ebics import EbicsKeyRing, EbicsBank, EbicsUser, EbicsClient
from math import floor
from fpdf import FPDF
from pypdf import PdfReader
from jinja2 import Environment, FileSystemLoader

s3_client = boto3.client('s3')
s3_bucket = 'ebics-test-bucket'
passphrase = 'mysecret'
s3_key = 'keys/mykeys'

HOST_ID = "EBIXQUAL"
USER_ID = "AMAGUMOLAITEST"
PARTNER_ID = "AMAGUMOLAITEST"
DEBTOR_BANK_NAME = "BNP Paribas"

GENERATE_BANK_LETTER_PATH = "/ebics/initialize/bank-letter"

class MyKeyRing(EbicsKeyRing):
    def _write(self, keydict):
        uploadByteStream = bytes(json.dumps(keydict).encode('UTF-8'))
        s3_client.put_object(Bucket = 'ebics-test-bucket', Key = 'keys/mykeys', Body = uploadByteStream)

def lambda_handler(event, context):
    keydict = {}
    # load keys from s3
    try:
        res = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        keys = res['Body']
        keydict = json.loads(keys.read())
        print(keydict)
    except s3_client.exceptions.NoSuchKey as e:
        keydict = {}
    except Exception as e:
        print(f"different error: {str(e)}")

    keyring = MyKeyRing(keydict, 'mysecret')
    bank = EbicsBank(keyring=keyring, hostid='EBIXQUAL', url='https://server-ebics.webank.fr:28103/WbkPortalFileTransfert/EbicsProtocol')
    user = EbicsUser(keyring=keyring, partnerid='AMAGUMOLAITEST', userid='AMAGUMOLAITEST', transport_only = True)

    # client = EbicsClient(bank, user, version = 'H003')

    if event.get('path') == GENERATE_BANK_LETTER_PATH:
        try: 
            ini_pdf = user.create_ini_letter(bankname=DEBTOR_BANK_NAME)
            s3_client.put_object(
                Bucket=s3_bucket, Key=f"{os.environ.get('S3_LETTER_FOLDER')}/ini_letter.pdf", Body=ini_pdf)

            versions = ['A005', 'X002', 'E002']
            versionName_t1 = ['Signature', "Authentification", 'Chiffrement']
            versionName_t2 = ['de signature', "d'authentification", 'de chiffrement']
            res = s3_client.get_object(Bucket=s3_bucket, Key=s3_cert)
            data = res['Body']
            certificates = json.loads(data.read())
            A005 = ''
            X002 = ''
            E002 = ''
            for cert_id, cert_list in certificates.items():
                for cert_data in cert_list:
                    # crt = cert_data.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                    if cert_id == 'A005':
                        A005 = cert_data
                    elif cert_id == 'E002':
                        E002 = cert_data
                    else:
                        X002 = cert_data

            # Opening templates
            TplEnv = Environment(loader=FileSystemLoader('letter_template/'))
            Tpl_letter = TplEnv.get_template('letter.txt')
            pdf_stream = io.BytesIO(ini_pdf)
            reader = PdfReader(pdf_stream)
            number_of_pages = len(reader.pages)

            a4_width_mm = 210
            pt_to_mm = 0.26
            fontsize_pt = 12
            fontsize_mm = fontsize_pt * pt_to_mm
            margin_bottom_mm = 2
            character_width_mm = 7 * pt_to_mm
            width_text = a4_width_mm / character_width_mm

            for page in range(number_of_pages):
                page_txt = reader.pages[page]
                text = page_txt.extract_text()
                lines = text.split("\n")
                hash = []

                for line in lines:
                    if "Hash (SHA-256)" in line:
                        Date = datetime.datetime.now(tz=pytz.timezone(
                            'Europe/Paris')).strftime("%d/%m/%Y %H:%M")
                        txt_letter = Tpl_letter.render(
                            HostID=HOST_ID,
                            PartnerID=PARTNER_ID,
                            UserID=USER_ID,
                            BankName=DEBTOR_BANK_NAME,
                            Certificate=A005 if versions[page] == 'A005' else (
                                X002 if versions[page] == 'X002' else E002),
                            Version=versions[page],
                            VersionName_t1=versionName_t1[page],
                            VersionName_t2=versionName_t2[page],
                            Date=Date,
                            Digest1=lines[lines.index(line)+1],
                            Digest2=lines[lines.index(line)+2])
                        pdf = FPDF(orientation='P', unit='mm', format='A4')
                        pdf.set_auto_page_break(auto=True, margin=margin_bottom_mm)
                        pdf.add_page()
                        pdf.set_font(family='Courier', size=fontsize_pt, style='I')
                        pdf.set_left_margin(20)
                        splitted = txt_letter.split('\n')
                        for spl_line in splitted:
                            spl_lines = textwrap.wrap(spl_line, floor(width_text))
                            if len(spl_lines) == 0:
                                pdf.ln()
                            else:
                                for wrap in spl_lines:
                                    pdf.cell(0, fontsize_mm, wrap, ln=1)
                                    pdf.ln()  # Add empty line below each line
                        pdf_output = pdf.output(dest='S')
                        pdf_bytes = pdf_output.encode('latin1')
                        s3_client.put_object(
                            Bucket=s3_bucket, Key=f"{{os.environ.get('S3_LETTER_FOLDER')}}/{versions[page]}.pdf", Body=pdf_bytes)

            return {
                'statusCode': 201,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'message': 'INI, HIA pdf letter stored in S3 successfully'})
            }
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body':json.dumps({'message': 'Can not load keys', 'error': str(e)})
            }
    else:
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "from Long with love transfer",
            }),
        }
