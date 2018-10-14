#include <iostream>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <keychain.h>

#include <QDebug>

#include <QSslCertificate>
#include <QSslKey>

using namespace std;

namespace Encrypting {
QByteArray generateRandom(int size){
    unsigned char *tmp = (unsigned char *)malloc(sizeof(unsigned char) * size);

    int ret = RAND_bytes(tmp, size);
    if (ret != 1) {
        qDebug() << "Random byte generation failed!";
        // Error out?
    }

    QByteArray result((const char *)tmp, size);
    free(tmp);

    return result;
}

QByteArray generatePassword(const QString& wordlist, const QByteArray& salt) {
    qDebug() << "Start encryption key generation!";

    const int iterationCount = 1024;
    const int keyStrength = 256;
    const int keyLength = keyStrength/8;

    unsigned char secretKey[keyLength];

    int ret = PKCS5_PBKDF2_HMAC_SHA1(
        wordlist.toLocal8Bit().constData(),     // const char *password,
        wordlist.size(),                        // int password length,
        (const unsigned char *)salt.constData(),                       // const unsigned char *salt,
        salt.size(),                            // int saltlen,
        iterationCount,                         // int iterations,
        keyLength,                              // int keylen,
        secretKey                               // unsigned char *out
    );

    if (ret != 1) {
        qDebug() << "Failed to generate encryption key";
        // Error out?
    }

    qDebug() << "Encryption key generated!";

    QByteArray password((const char *)secretKey, keyLength);
    return password;
}

QByteArray encryptPrivateKey(
        const QByteArray& key,
        const QByteArray& privateKey,
        const QByteArray& salt
        ) {

    QByteArray iv = generateRandom(12);

    EVP_CIPHER_CTX *ctx;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        qDebug() << "Error creating cipher";
    }

    /* Initialise the decryption operation. */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        qDebug() << "Error initializing context with aes_256";
    }

    // No padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* Set IV length. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) {
        qDebug() << "Error setting iv length";
    }

    /* Initialise key and IV */
    if(!EVP_EncryptInit_ex(ctx, NULL, NULL, (unsigned char *)key.constData(), (unsigned char *)iv.constData())) {
        qDebug() << "Error initialising key and iv";
    }

    // We write the base64 encoded private key
    QByteArray privateKeyB64 = privateKey.toBase64();

    // Make sure we have enough room in the cipher text
    unsigned char *ctext = (unsigned char *)malloc(sizeof(unsigned char) * (privateKeyB64.size() + 32));

    // Do the actual encryption
    int len = 0;
    if(!EVP_EncryptUpdate(ctx, ctext, &len, (unsigned char *)privateKeyB64.constData(), privateKeyB64.size())) {
        qDebug() << "Error encrypting";
    }

    int clen = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ctext + len, &len)) {
        qDebug() << "Error finalizing encryption";
    }
    clen += len;

    /* Get the tag */
    unsigned char *tag = (unsigned char *)calloc(sizeof(unsigned char), 16);
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        qDebug() << "Error getting the tag";
    }

    QByteArray cipherTXT((char *)ctext, clen);
    cipherTXT.append((char *)tag, 16);

    QByteArray result = cipherTXT.toBase64();
    result += "fA==";
    result += iv.toBase64();
    result += "fA==";
    result += salt.toBase64();

    return result;
}

QByteArray BIO2ByteArray(BIO *b) {
    int pending = BIO_ctrl_pending(b);
    char *tmp = (char *)calloc(pending+1, sizeof(char));
    BIO_read(b, tmp, pending);

    QByteArray res(tmp, pending);
    free(tmp);

    return res;
}

QByteArray privateKeyToPem(const QSslKey key) {
    BIO *privateKeyBio = BIO_new(BIO_s_mem());
    QByteArray privateKeyPem = key.toPem();
    BIO_write(privateKeyBio, privateKeyPem.constData(), privateKeyPem.size());
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(privateKeyBio, NULL, NULL, NULL);

    BIO *pemBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(pemBio, pkey, NULL, NULL, 0, NULL, NULL);
    QByteArray pem = BIO2ByteArray(pemBio);

    BIO_free_all(privateKeyBio);
    BIO_free_all(pemBio);
    EVP_PKEY_free(pkey);

    return pem;
}
}

int main()
{
    cout << "Hello World!" << endl;

    //generate key
    const char privatekey[] = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDsn0JKS/THu328z1IgN0VzYU53HjSX03WJIgWkmyTaxbiKpoJaKbksXmfSpgzVGzKFvGfZ03fwFrN7Q8P8R2e8SNiell7mh1TDw9/0P7Bt/ER8PJrXORo+GviKHxaLr7Y0BJX9i/nW/L0L/VaE8CZTAqYBdcSJGgHJjY4UMf892ZPTa9T2Dl3ggdMZ7BQ2kiCiCC3qV99b0igRJGmmLQaGiAflhFzuDQPMifUMq75wI8RSRPdxUAtjTfkl68QHu7Umyeyy33OQgdUKaTl5zcS3VSQbNjveVCNM4RDH1RlEc+7Wf1BY8APqT6jbiBcROJD2CeoLH2eiIJCi+61ZkSGfAgMBAAECggEBALFStCHrhBf+GL9a+qer4/8QZ/X6i91PmaBX/7SYk2jjjWVSXRNmex+V6+Y/jBRT2mvAgm8J+7LPwFdatE+lz0aZrMRD2gCWYF6Itpda90OlLkmQPVWWtGTgX2ta2tF5r2iSGzk0IdoL8zw98Q2UzpOcw30KnWtFMxuxWk0mHqpgp00g80cDWg3+RPbWOhdLp5bflQ36fKDfmjq05cGlIk6unnVyC5HXpvh4d4k2EWlXrjGsndVBPCjGkZePlLRgDHxT06r+5XdJ+1CBDZgCsmjGz3M8uOHyCfVW0WhB7ynzDTagVgz0iqpuhAi9sPt6iWWwpAnRw8cQgqEKw9bvKKECgYEA/WPi2PJtL6u/xlysh/H7A717CId6fPHCMDace39ZNtzUzc0nT5BemlcF0wZ74NeJSur3Q395YzB+eBMLs5p8mA95wgGvJhM65/J+HX+k9kt6Z556zLMvtG+j1yo4D0VEwm3xahB4SUUP+1kD7dNvo4+8xeSCyjzNllvYZZC0DrECgYEA7w8pEqhHHn0a+twkPCZJS+gQTB9Rm+FBNGJqB3XpWsTeLUxYRbVGk0iDve+eeeZ41drxcdyWP+WcL34hnrjgI1Fo4mK88saajpwUIYMy6+qMLY+jC2NRSBox56eH7nsVYvQQK9eKqv9wbB+PF9SwOIvuETN7fd8mAY02UnoaaU8CgYBoHRKocXPLkpZJuuppMVQiRUi4SHJbxDo19Tp2w+y0TihiJ1lvp7I3WGpcOt3LlMQktEbExSvrRZGxZKH6Og/XqwQsYuTEkEIz679F/5yYVosE6GkskrOXQAfh8Mb3/04xVVtMaVgDQw0+CWVD4wyL+BNofGwBDNqsXTCdCsfxAQKBgQCDv2EtbRw0y1HRKv21QIxoju5cZW4+cDfVPN+eWPdQFOs1H7wOPsc0aGRiiupV2BSEF3O1ApKziEE5U1QH+29bR4R8L1pemeGX8qCNj5bCubKjcWOz5PpouDcEqimZ3q98p3E6GEHN15UHoaTkx0yO/V8oj6zhQ9fYRxDHB5ACtQKBgQCOO7TJUO1IaLTjcrwS4oCfJyRnAdz49L1AbVJkIBK0fhJLecOFu3ZlQl/RStQb69QKb5MNOIMmQhg8WOxZxHcpmIDbkDAm/J/ovJXFSoBdOr5ouQsYsDZhsWW97zvLMzg5pH9/3/1BNz5q3Vu4HgfBSwWGt4E2NENj+XA+QAVmGA==";
    const char key[] = "YXbFCAnfUsMZMizGs7rTeg==";
    const char mnemonic[] = "mnemonic";

    QSslKey _privateKey = QSslKey(privatekey, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);

    auto salt = Encrypting::generateRandom(40);
    auto secretKey = Encrypting::generatePassword(key, salt);
    auto cryptedText = Encrypting::encryptPrivateKey(secretKey, Encrypting::privateKeyToPem(_privateKey), salt);

    qDebug() << "Crypted text: " << cryptedText;

    return 0;
}
