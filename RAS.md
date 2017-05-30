## RSA

### RSA 생성

* PEM public 키로 RSA 생성하기
```c++
unsigned char *key = "PEM 형식의 public 키";
BIO *bio = BIO_new_mem_buf(key, -1);
RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
```

* PEM private 키로 RSA 생성하기
```c++
unsigned char *key = "PEM 형식의 private 키";
BIO *bio = BIO_new_mem_buf(key, -1);
RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
```

* RSA 생성
```c++
int bits = 2048;

BIGNUM *bn = BN_new();

if ( BN_set_word(bn, RSA_F4) != 1 ) throw "BN_set_word fail";

RSA *rsa = RSA_new();

if ( RSA_generate_key_ex(rsa, bits, bn, NULL) != 1 ) throw "RSA_generate_key_ex fail";
```

* 인증서(.cer) 파일로 RSA 생성하기
```c++
char path[256] = ".cer 경로";

FILE* fp = fopen(path, "rb");
if(fp == NULL) throw "File open fail";

X509 *cert = d2i_X509_fp(fp, NULL);
if(cert == NULL) throw "X509 parsing fail";

EVP_PKEY *pkey = X509_get_pubkey(cert);
if (pkey == NULL) throw "public key getting fail";

int id = EVP_PKEY_id(pkey);
if ( id != EVP_PKEY_RSA ) throw "is not RAS Encryption file";

RSA *rsa = EVP_PKEY_get1_RSA(pkey);
if ( rsa == NULL ) throw "EVP_PKEY_get1_RSA fail";
```

* PCKS12(.p12) 파일로 RSA 생성하기
```c++
char path[256] = ".p12 경로";
char passwd[128] = ".p12 파일 암호"

FILE* fp = fopen(path, "rb");
if(fp == NULL) throw "File open fail";

PKCS12 *pkcs12 = d2i_PKCS12_fp(fp, NULL);
if(pkcs12 == NULL) throw "PKCS12 load fail";

EVP_PKEY *pkey = NULL;
X509 *cert = NULL;
int result = PKCS12_parse(pkcs12, passwd, &pkey, &cert, NULL);
if ( result != 1 ) throw "PKCS12 parsing fail";

RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) throw "EVP_PKEY_get1_RSA fail";
```

* DER 파일 읽기
```c++
int size = 0;
FILE* fp = NULL;

try {
    fp = fopen(filename, "rb");
    if ( fp == NULL ) throw L"File open error";

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    if ( size <= 0 ) throw L"File size is zero";

    fseek(fp, 0, SEEK_SET);

    if ( *out_len < size ) throw L"Out of memeory";

    if ( fread(out, sizeof(unsigned char), size, fp) != size ) throw L"File read error";

    *out_len = size;
}
catch(TCHAR *msg)    {
    MessageBox(msg);
    isSuccess = false;
}

if ( fp ) fclose(fp);
```

* DER 형식의 private key로 RSA 생성

    * DER 형식의 private key 생성 명령
    ```bash
    openssl rsa -inform PEM -outform DER -in privatekey.pem -out privatekey.der
    ```

    * RSA 생성 코드
    ```c++
    const unsigned char *key = { /*DER 형식의 private*/ };
    const int key_len = 1192; // key의 길이

    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &key, key_len);
    if ( pkey == NULL ) throw "RSA private Key read fail";

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) throw "EVP_PKEY_get1_RSA fail";
    ```

* DER 형식의 public key로 RSA 생성(294byte)
    * DER 형식의 public key 생성 명령
    ```bash
    openssl rsa -pubin -in publickey.pem -inform PEM -pubout -out publickey.der -outform DER
    ```
    * RSA 생성 코드
    ```c++
    RSA *rsa = d2i_RSA_PUBKEY(NULL, &key, key_len);
    ```

* DER 형식의 public key로 RSA 생성(993byte)
    * DER 형식의 public key 생성 명령
    ```bash
    openssl x509 -in ca.crt -pubkey -out ca_publickey.der -outform DER
    ```
    * RSA 생성 코드
    ```c++
    X509 *cert = d2i_X509(NULL, &key, key_len);
    if ( cert == NULL ) throw "RSA public key read fail";

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL) throw "public key getting fail";

    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) throw "is not RAS Encryption file";

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    ```

* 순수한 public key(256byte) 로 RSA 생성하기
```c++
/**
 * @brief ASN1 포로트콜용 길이 문자열을 HEX STRING으로 만든다.
 * @param [in] size byte data 길이
 * @param [out] out HEX STRING
 * @return out
 */
inline char *ASN1_MAKE_HEX_LENGTH(int size, char *out)
{
    if( size < 0x81 ) sprintf(out, "%02X", size);
    else if ( size == 0x81 ) sprintf(out, "81%02X", size);
    else if ( size > 0x81 ) sprintf(out, "82%04X", size);

    return out;
}


const unsigned char *key = "HEX String의 256byte public 키";

char hex[540+1] = "";
unsigned char raw_buf[4096], *p;
int raw_size = 0;
char seq_length[6+1]="", int_length[6+1]="";
int seq_size_of_byte, int_size_of_byte = (strlen((const char*)key) +2) / 2; // include first "00"

ASN1_MAKE_HEX_LENGTH(int_size_of_byte, int_length);

seq_size_of_byte = 1 + (strlen(int_length)/2) + int_size_of_byte    // public key block
                    + 5;                                            // exponent block

ASN1_MAKE_HEX_LENGTH(seq_size_of_byte, seq_length);

sprintf(hex, "30%s02%s00%s0203010001", seq_length, int_length, key);

// public key size를 256byte로 고정하는 경우
//sprintf(hex, "3082010A0282010100%s0203010001", key);

p = raw_buf;

hex2binary(raw_buf, &raw_size, hex);

RSA *rsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&p, raw_size);
if ( rsa == NULL ) throw "EVP_PKEY_get1_RSA fail";
```

### RSA 에서 추출

* RSA에서 PEM public 키 추출
```c++
BIO *bio = BIO_new(BIO_s_mem());

// -----BEGIN RSA PUBLIC KEY----- 이런 해더로 생성됨
//if ( PEM_write_bio_RSAPublicKey(bio, rsa) != 1 )  throw "PEM_write_bio_RSAPublicKey fail";

// -----BEGIN PUBLIC KEY----- 이런 해더로 생성됨
if ( PEM_write_bio_RSA_PUBKEY(bio, rsa) != 1 )  throw "PEM_write_bio_RSAPublicKey fail";

int size = BIO_get_mem_data(bio, &p);
if ( size <= 0 ) throw "Public size is zero";
size++; // include null

char *buffer = new char[size];

int read_size = BIO_read(bio, buffer, size-1);
if ( read_size != size-1 ) throw "Public read fail";
```

* RSA에서 PEM private 키 추출
```c++
BIO *bio = BIO_new(BIO_s_mem());

if ( PEM_write_bio_RSAPrivateKey(bio, _rsa, NULL, NULL, 0, NULL, NULL) != 1) throw "PEM_write_bio_RSAPrivateKey fail";

int size = BIO_get_mem_data(bio, &p);
if ( size <= 0 ) throw "Private size is zero";
size++; // include null

char *buffer = new char[size];

int read_size = BIO_read(bio, buffer, size-1);
if ( read_size != size-1 ) throw "Private read fail";
```

* RSA에서 순수한 Public 키(256byte) 추출 하기(DER 파싱)
```c++
/**
  @breif der를 한번 파싱한다.
  @param [in] in 파싱 시작위치
  @param [out] tag 태그 type
  @param [out] length data length
  @param [out] data data 시작위치
  @return true 성공
*/
bool parsingDer(const unsigned char *in, unsigned char *tag, int *length, unsigned char **data)
{
    int offset = 0;
    *tag = in[0];

    if ( in[++offset] == 0x82 ) {
        *length = (int)(in[offset+1] << 8 | in[offset+2]);
        offset += 2;
    } else {
        *length = (int)(in[++offset]);
    }

    *data = ( unsigned char *)&in[++offset];

    return true;
}

unsigned char out[256];
unsigned char tag, *buf, *start_pos, *data_pos;

int data_len = i2d_RSAPublicKey( rsa, &buf );
if ( data_len < 0 ) throw "Fail get public key from rsa";

start_pos = buf;

parsingDer(start_pos, &tag, &data_len, &data_pos);
if ( tag != 0x30 ) throw "Fail parsing at SEQUENCE";

start_pos = data_pos;
parsingDer(start_pos, &tag, &data_len, &data_pos);
if ( tag != V_ASN1_INTEGER ) throw "Fail parsing at INTEGER";

memcpy(out, &(data_pos[1]), data_len-1);
```

* RSA에서 시작일 추출
```c++
ASN1_TIME* atime_before = NULL;

atime_before = X509_get_notBefore(_cert);
if ( atime_before == NULL ) throw "X509_get_notBefore fail";
```

* RSA에서 만료일 추출
```c++
ASN1_TIME* atime_after = NULL;

atime_after = X509_get_notAfter(_cert);

if ( atime_after == NULL ) throw "X509_get_notAfter fail";
```

### ASN1_TIME을 문자열로 변환
```c++
char* ASN1_TIME_to_string(const ASN1_TIME* time, char out[DT_STRING_LENGTH])
{
    struct tm t;
    const char* str = (const char*) time->data;
    size_t i = 0;

    memset(&t, 0, sizeof(t));

    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        t.tm_year = (str[i++] - '0') * 10;
        t.tm_year += (str[i++] - '0');
        if (t.tm_year < 70)
            t.tm_year += 100;
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        t.tm_year = (str[i++] - '0') * 1000;
        t.tm_year+= (str[i++] - '0') * 100;
        t.tm_year+= (str[i++] - '0') * 10;
        t.tm_year+= (str[i++] - '0');
        t.tm_year -= 1900;
    }
    t.tm_mon  = (str[i++] - '0') * 10;
    t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
    t.tm_mday = (str[i++] - '0') * 10;
    t.tm_mday+= (str[i++] - '0');
    t.tm_hour = (str[i++] - '0') * 10;
    t.tm_hour+= (str[i++] - '0');
    t.tm_min  = (str[i++] - '0') * 10;
    t.tm_min += (str[i++] - '0');
    t.tm_sec  = (str[i++] - '0') * 10;
    t.tm_sec += (str[i++] - '0');

    /* Note: we did not adjust the time based on time zone information */
    time_t tt = mktime(&t);
    //strftime(out, DT_STRING_LENGTH, "%Y-%m-%d %H:%M:%S", localtime(&tt));
    strftime(out, DT_STRING_LENGTH, "%Y%m%d", localtime(&tt));

    return out;
}
```

### 암호화

* public키로 생성한 RSA로 암호화
```c++
RSA_public_encrypt(flen, from, to, rsa, padding);
```

* private키로 생성한 RSA로 암호화
```c++
RSA_private_encrypt(flen, from, to, rsa, padding);
```

### 복호화

* public키로 생성한 RSA로 복호화
```c++
RSA_public_decrypt(flen, from, to, rsa, padding);
```

* private키로 생성한 RSA로 복호화
```c++
RSA_private_decrypt(flen, from, to, rsa, padding);
```

### base64

* 인코딩
```c++
int raw_size = 256;
unsigned char raw[256] ={/* RAWDATA */};

int bas64_size = 1.5 * raw_size;
char *out = new char[bas64_size];

bas64_size = EVP_EncodeBlock((unsigned char*)out, (const unsigned char*)raw, raw_size);
out[bas64_size++] = 0;
```

### 기타 함수

* hex string을 binary(RAWDATA)로 만들기
```c++
void hex2binary(unsigned char *dst, int *dst_len, const char *src)
{
    int src_len = strlen(src);
    char *end =0;
    char buf[3] = {0,};
    int i=0;

    for(i=0; i<src_len; i++) {
        strncpy(buf, &src[i*2], 2);
        dst[i] = (char)strtol(buf, &end, 16);
    }

    *dst_len = i/2;

    return;
}
```
