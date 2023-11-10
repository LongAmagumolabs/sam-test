import json
import io
import datetime
import textwrap
import os
import boto3
import fintech
import pytz
fintech.register()
from jinja2 import Environment, FileSystemLoader
from pypdf import PdfReader
from fpdf import FPDF
from math import floor
from fintech.ebics import EbicsKeyRing, EbicsBank, EbicsUser, EbicsClient
from fintech.sepa import Account, SEPACreditTransfer

cognito_client = boto3.client('cognito-idp')
s3_client = boto3.client('s3')
s3_bucket = os.environ.get('S3_BUCKET')
passphrase = os.environ.get('PASSPHRASE')
s3_key = f"{os.environ.get('S3_KEY_FOLDER')}/mykeys"
s3_cert = f"{os.environ.get('S3_KEY_FOLDER')}/certs"

USER_POOL_ID = os.environ.get('USER_POOL_ID')
APP_CLIENT_ID = os.environ.get('APP_CLIENT_ID')

HOST_ID = os.environ.get('HOST_ID')
HOST_URL = os.environ.get('HOST_URL')
USER_ID = os.environ.get('USER_ID')
PARTNER_ID = os.environ.get('PARTNER_ID')
VERSION = os.environ.get('VERSION')

DEBTOR_IBAN = os.environ.get('DEBTOR_IBAN') #International Bank Account Number
DEBTOR_BIC = os.environ.get('DEBTOR_BIC') #Bank Identifier Code
DEBTOR_BANK_NAME = os.environ.get('DEBTOR_BANK_NAME')

VIREMENTS_SCT_URG = "VIREMENTS_SCT_URG"
VIREMENTS_SCT = "VIREMENTS_SCT"

SIGN_IN_PATH = "/ebics/sign-in"
INIT_CONNECTION_PATH = "/ebics/initialize"
STORE_BANK_KEYS_PATH = "/ebics/initialize/store-bank-keys"
GENERATE_BANK_LETTER_PATH = "/ebics/initialize/bank-letter"
SEND_CREDIT_TRANSFER_PATH = "/ebics/credit-transfer"
SEND_CREDIT_TRANSFER_GROUP_PATH = "/ebics/credit-transfer-group"
REATRIEVE_STATMENT_PATH = "/ebics/retrieve-statement"

def b36encode(number):
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base36 = ""
    while number:
        number, i = divmod(number, 36)
        base36 = chars[i] + base36
    return base36 or "0"
def b36decode(number):
    return int(number, 36)
class EbicsBank(EbicsBank):
    """
    EBICS protocol version H003 requires generation of the OrderID.
    The OrderID must be a string between 'A000' and 'ZZZZ' and
    unique for each partner id.
    """
    order_ids_s3_key = f"{os.environ.get('S3_IDS_FOLDER')}/order_ids.json"

    def _next_order_id(self, partnerid):
        try:
            order_ids = json.loads(s3_client.get_object(Bucket=s3_bucket, Key=self.order_ids_s3_key)['Body'].read().decode('utf-8'))
        except s3_client.exceptions.NoSuchKey:
            order_ids = {}

        order_id = order_ids.setdefault(partnerid, "A000")
        diff = (b36decode(order_id) - 466559) % 1213056
        order_ids[partnerid] = b36encode(466560 + diff)

        # Save 'order_ids.json' back to S3
        s3_client.put_object(Bucket=s3_bucket, Key=self.order_ids_s3_key, Body=json.dumps(order_ids, indent=4))

        return order_id

class MyKeyRing(EbicsKeyRing):
    def _write(self, keydict):
        uploadByteStream = bytes(json.dumps(keydict).encode('UTF-8'))
        s3_client.put_object(Bucket = s3_bucket, Key = s3_key, Body = uploadByteStream)

def lambda_handler(event, context):
    print(event)
    try:
        # load keys from s3
        try:
            res = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
            keys = res['Body']
            keydict = json.loads(keys.read())
        except s3_client.exceptions.NoSuchKey as e:
            keydict = {}
        except Exception as e:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body':json.dumps({'message': 'Can not load keys', 'error': str(e)})
            }

        keyring = MyKeyRing(keydict, passphrase)
        bank = EbicsBank(keyring=keyring, hostid = HOST_ID, url = HOST_URL)
        user = EbicsUser(keyring=keyring, partnerid = PARTNER_ID, userid = USER_ID, transport_only=True)

        if event.get('path') == SIGN_IN_PATH and event.get('httpMethod') == 'POST':

            json_data = json.loads(event.get('body'))

            email = json_data.get('email')
            password = json_data.get('password')

            response = cognito_client.admin_initiate_auth(
                UserPoolId= USER_POOL_ID,
                ClientId=APP_CLIENT_ID,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password
                }
            )
            accessToken = response['AuthenticationResult']['AccessToken']
            refreshToken = response['AuthenticationResult']['RefreshToken']
            idToken = response['AuthenticationResult']['IdToken']
            expiresIn = response['AuthenticationResult']['ExpiresIn']
            tokenType = response['AuthenticationResult']['TokenType']

            return{
                'statusCode': 200,
                'headers': {'content-type': 'application/json'},
                'body': json.dumps({
                    'AccessToken': accessToken,
                    'ExpiresIn': expiresIn,
                    'TokenType': tokenType,
                    'RefreshToken': refreshToken,
                    'IdToken': idToken,
                })
            }
        elif event.get('path') == INIT_CONNECTION_PATH:
            try:
                #create keys (A - E - X) for user and automatically save to keyring
                user.create_keys(keyversion='A005', bitlength=2048)
                user.create_certificates(
                    commonName= os.environ.get('COMMON_NAME'),
                    organizationName= os.environ.get('ORGANIZATION'),
                    organizationalUnitName = os.environ.get('ORGANIZATION_UNIT'),
                    stateOrProvinceName= os.environ.get('STATE'),
                    localityName = os.environ.get('LOCALITY'),
                    countryName= os.environ.get('COUNTRY'),
                )

                cert = user.export_certificates()
                cert_str = json.dumps(cert, indent=4)
                s3_client.put_object(Bucket=s3_bucket, Key=s3_cert, Body = cert_str)

                client = EbicsClient(bank, user, version=VERSION)
                client.INI()
                client.HIA()
                return {
                    'statusCode': 201,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'message': 'INI, HIA orders sended to the bank!'})
                }
            except Exception as e:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body':json.dumps({'error': str(e)})
                }

        elif event.get('path') == STORE_BANK_KEYS_PATH:
            client = EbicsClient(bank, user, version=VERSION)
            bankKeys = client.HPB()
            bank.activate_keys()
            return {
                'statusCode': 201,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'bankKeys': bankKeys, 'message': 'bank connection is created, response bank public keys [E002, X002]',})
            }

        elif event.get('path') == GENERATE_BANK_LETTER_PATH:

            ini_pdf = user.create_ini_letter(bankname = DEBTOR_BANK_NAME)
            s3_client.put_object(Bucket=s3_bucket, Key=f"{os.environ.get('S3_LETTER_FOLDER')}/ini_letter.pdf", Body=ini_pdf)

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
                        Date = datetime.datetime.now(tz=pytz.timezone('Europe/Paris')).strftime("%d/%m/%Y %H:%M")
                        txt_letter = Tpl_letter.render(
                            HostID = HOST_ID,
                            PartnerID = PARTNER_ID,
                            UserID = USER_ID,
                            BankName = DEBTOR_BANK_NAME,
                            Certificate = A005 if versions[page] == 'A005' else (X002 if versions[page] == 'X002' else E002),
                            Version = versions[page],
                            VersionName_t1 = versionName_t1[page],
                            VersionName_t2 = versionName_t2[page],
                            Date = Date,
                            Digest1 = lines[lines.index(line)+1],
                            Digest2 = lines[lines.index(line)+2])
                        pdf = FPDF(orientation='P', unit='mm', format='A4')
                        pdf.set_auto_page_break(auto=True, margin=margin_bottom_mm)
                        pdf.add_page()
                        pdf.set_font(family='Courier', size=fontsize_pt, style = 'I')
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
                        s3_client.put_object(Bucket=s3_bucket, Key=f"{os.environ.get('S3_LETTER_FOLDER')}/{versions[page]}.pdf", Body=pdf_bytes)

            return {
                'statusCode': 201,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'message': 'INI, HIA pdf letter stored in S3 successfully'})
            }

        elif event.get('path') == SEND_CREDIT_TRANSFER_PATH:
            try:
                client = EbicsClient(bank, user, version=VERSION)
                json_data = json.loads(event.get('body'))
                if json_data.get('OrderType') == VIREMENTS_SCT:
                    debtor = Account((DEBTOR_IBAN,DEBTOR_BIC), DEBTOR_BANK_NAME)
                    creditor = Account(
                        (json_data.get('AccountReference').get('IBAN'),
                        "" if json_data.get('AccountReference').get('BIC') is None else json_data.get('AccountReference').get('BIC')),
                        json_data.get('AccountReference').get('FullName')
                    )
                    sct = SEPACreditTransfer(
                        account = debtor,
                        scheme = 'pain.001.001.03'
                    )

                    if json_data.get('TransactionData') is None:
                        return {
                            'statusCode': 500,
                            'headers': {'Content-Type': 'application/json'},
                            'body':json.dumps({'message': 'TransactionData null'})
                        }
                    trans = sct.add_transaction(
                        account  = creditor,
                        amount  = json_data.get('TransactionData').get('Amount'),
                        purpose = json_data.get('TransactionData').get('purpose'),
                        due_date = json_data.get('Date')
                    )
                    # Render the SEPA document
                    data = sct.render()
                    uploadId = client.FUL(filetype = 'xml', data = data, TEST = 'TRUE')
                    key_sct = f"{os.environ.get('S3_TRANSFER_FOLDER')}/sepa_credit_transfer_{uploadId}.xml"
                    s3_client.put_object(Bucket = s3_bucket, Key = key_sct, Body = data)
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json'},
                        'body':json.dumps({'id': uploadId, 'message': 'upload successed'})
                    }
                elif json_data.get('OrderType') == VIREMENTS_SCT_URG:
                    debtor = Account((DEBTOR_IBAN,DEBTOR_BIC), DEBTOR_BANK_NAME)
                    creditor = Account(
                        (json_data.get('AccountReference').get('IBAN'),
                        "" if json_data.get('AccountReference').get('BIC') is None else json_data.get('AccountReference').get('BIC')),
                        json_data.get('AccountReference').get('FullName')
                    )
                    sct = SEPACreditTransfer(
                        account = debtor,
                        scheme = 'pain.001.001.03',
                        type = 'HIGH'
                    )

                    if json_data.get('TransactionData') is None:
                        return {
                            'statusCode': 500,
                            'headers': {'Content-Type': 'application/json'},
                            'body':json.dumps({'message': 'TransactionData null'})
                        }
                    trans = sct.add_transaction(
                        account  = creditor,
                        amount  = json_data.get('TransactionData').get('Amount'),
                        purpose = json_data.get('TransactionData').get('purpose'),
                        due_date = json_data.get('Date')
                    )
                    # Render the SEPA document
                    data = sct.render()
                    uploadId = client.FUL(filetype = 'xml', data = data, TEST = 'TRUE')
                    key_sct = f"{os.environ.get('S3_TRANSFER_FOLDER')}/sepa_credit_transfer_{uploadId}_urg.xml"
                    s3_client.put_object(Bucket = s3_bucket, Key = key_sct, Body = data)
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json'},
                        'body':json.dumps({'id': uploadId, 'message': 'upload successed'})
                    }

                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body':json.dumps({'message': 'invalid OrderType'})
                }
            except Exception as e:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body':json.dumps({'error': str(e)})
                }
        elif event.get('path') == SEND_CREDIT_TRANSFER_GROUP_PATH:
            client = EbicsClient(bank, user, version=VERSION)
            debtor = Account((DEBTOR_IBAN,DEBTOR_BIC), DEBTOR_BANK_NAME)
            transfers_group = json.loads(event.get('body'))
            sct = SEPACreditTransfer(
                account = debtor,
                scheme = 'pain.001.001.03'
            )
            sct_urg = SEPACreditTransfer(
                account = debtor,
                scheme = 'pain.001.001.03',
                type = 'HIGH'
            )
            uploadIds = []
            missingTransfers = []
            errors = []
            for transfer in transfers_group:
                if (transfer.get('InstructionPriority').upper() == 'HIGH'):
                    try:
                        creditor = Account(
                            (transfer.get('IBAN'),
                            "" if transfer.get('BIC') is None else transfer.get('BIC')),
                            transfer.get('FullName')
                        )
                        trans_urg = sct_urg.add_transaction(
                            account  = creditor,
                            amount  = transfer.get('Amount'),
                            purpose = transfer.get('purpose'),
                            due_date = transfer.get('Date')
                        )
                    except Exception as e:
                        missingTransfers.append(transfer.get('IBAN'))
                        errors.append(str(e))

                elif (transfer.get('InstructionPriority').upper() == 'NORM'):
                    try:
                        creditor = Account(
                            (transfer.get('IBAN'),
                            "" if transfer.get('BIC') is None else transfer.get('BIC')),
                            transfer.get('FullName')
                        )
                        trans = sct.add_transaction(
                            account  = creditor,
                            amount  = transfer.get('Amount'),
                            purpose = transfer.get('purpose'),
                            due_date = transfer.get('Date')
                        )
                    except Exception as e:
                        missingTransfers.append(transfer.get('IBAN'))
                        errors.append(str(e))

                else:
                    missingTransfers.append(transfer.get('IBAN'))
                    errors.append('invalid InstructionPriority')
            if len(sct_urg) != 0:
                # Render the SEPA urgent document
                data_urg = sct_urg.render()
                uploadId = client.FUL(filetype = 'xml', data = data_urg, TEST = 'TRUE')
                uploadIds.append(uploadId)
                key_sct = f"{os.environ.get('S3_TRANSFER_FOLDER')}/sepa_credit_transfer_{uploadId}.xml"
                s3_client.put_object(Bucket = s3_bucket, Key = key_sct, Body = data_urg)

            if len(sct) != 0:
                # Render the SEPA document
                data = sct.render()
                uploadId = client.FUL(filetype = 'xml', data = data, TEST = 'TRUE')
                uploadIds.append(uploadId)
                key_sct_urg = f"{os.environ.get('S3_TRANSFER_FOLDER')}/sepa_credit_transfer_{uploadId}_urg.xml"
                s3_client.put_object(Bucket = s3_bucket, Key = key_sct_urg, Body = data)

            return{
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'ids': uploadIds, 'message': 'Some transfers upload failed, double check input properties' if errors is None else 'All transfers upload successfully', 'accounts': missingTransfers, 'errors': errors})
            }
        elif event.get('path') == REATRIEVE_STATMENT_PATH:
            client = EbicsClient(bank, user, version=VERSION)
            # stm = client.CRZ(start = '2023-10-22', end = '2023-10-23') # payment status report
            # stm = client.Z01(start = '2023-10-22', end = '2023-10-23') # payment status report
            stm = client.C53(start = '2023-10-22', end = '2023-10-23') # bank to customer statement
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body':json.dumps({'statement': stm})
            }
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body':json.dumps({'error': str(e)})
        }