import json
import boto3
import gnupg
import os
import base64

s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')

def setup_gpg():
    gpg_home = '/tmp/.gnupg'
    os.makedirs(gpg_home, exist_ok=True)
    gpg = gnupg.GPG(gnupghome=gpg_home)
    return gpg

def get_secret(secret_name):
    response = secrets_client.get_secret_value(SecretId=secret_name)
    secret = json.loads(response['SecretString'])
    private_key_base64 = secret['private_key']
    passphrase = secret['passphrase']
    private_key = base64.b64decode(private_key_base64).decode('utf-8')
    return private_key, passphrase

def import_private_key(gpg, key_data, passphrase):
    import_result = gpg.import_keys(key_data)
    if import_result.count == 0:
        raise Exception("Failed to import private key")
    return import_result.fingerprints[0]

def decrypt_file(gpg, encrypted_data, passphrase):
    decrypted_data = gpg.decrypt(encrypted_data, passphrase=passphrase)
    if not decrypted_data.ok:
        raise Exception(f"Decryption failed: {decrypted_data.stderr}")
    return decrypted_data.data

def lambda_handler(event, context):
    print(json.dumps(event))
    destination_bucket = os.environ['DESTINATION_BUCKET']
    secret_name = os.environ['SECRET_NAME']

    # Setup GPG
    gpg = setup_gpg()

    # Get the private key and passphrase from Secrets Manager
    private_key, passphrase = get_secret(secret_name)

    # Import the private key
    import_private_key(gpg, private_key, passphrase)

    # Process each file in the event
    for record in event['Records']:
        source_bucket = record['s3']['bucket']['name']
        source_key = record['s3']['object']['key']

        # Get the encrypted file from S3
        encrypted_object = s3_client.get_object(Bucket=source_bucket, Key=source_key)
        encrypted_data = encrypted_object['Body'].read()

        # Decrypt the file
        decrypted_data = decrypt_file(gpg, encrypted_data, passphrase)

        # Define the destination key
        destination_key = source_key.replace('.gpg', '')

        # Put the decrypted file into the destination S3 bucket
        s3_client.put_object(Bucket=destination_bucket, Key=destination_key, Body=decrypted_data)

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Files decrypted and uploaded to S3"
        })
    }
