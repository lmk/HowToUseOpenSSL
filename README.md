# OpenSSL

## OpenSSL 명령행 사용법

### RSA
  - Private key 와 인증서 생성
    ```bash
    $ openssl req -x509 -sha1 -nodes -days 1826 -newkey rsa:2048 -keyout rsaprivkey.pem -out ca.crt
    ````
  - 인증서 검증
    ```bash
    $ openssl x509 -in ca.crt -text -noout
    ```
  - 키 검증
    ```bash
    $ openssl rsa -in rsaprivkey.pem -check
    ```
  - Private key pkcs12 형식으로 변환
    ```bash
    $ openssl pkcs12 -export -nocerts -inkey rsaprivkey.pem -out rsaprivkey.p12
    ```
  - Private key pkcs12 검증
    ```bash
    $ openssl pkcs12 -info -in rsaprivkey.p12
    ```

### DSA
  - 키 파라미터 생성
    ```bash
    $ openssl dsaparam -out dsaparam.pem 2048
    ```
  - Private key 생성
    ```bash
    $ openssl gendsa -out dsaprivkey.pem dsaparam.pem
    ```
  - Private key 검증
    ```bash
    $ openssl dsa -in dsaprivkey.pem -inform pem
    ```
  - Private key der 형식으로 변환
    ```bash
    $ openssl pkcs8 -topk8 -inform PEM -outform DER -in dsaprivkey.pem -out dsaprivkey.der -nocrypt
    ```
  - Private key der 검증
    ```bash
    $ openssl dsa -in dsaprivkey.der -inform der
    ```
  - Pubilc key 생성
    ```bash
    $ openssl dsa -in dsaprivkey.pem -outform DER -pubout -out dsapubkey.der
    ```
  - Pubilc key 검증
    ```bash
    $ openssl dsa -pubin -in dsapubkey.der -inform der
    ```
### 파일 종류
   * DER: ASN.1 프로토콜을 사용한 TLV(Tag + Length + Value) 형식의 Binary 파일
   * PEM: DER을 base64로 인코딩한 Text 파일
      - Header와 Tail이 추가된다.
        - "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"
          - PEM_write_bio_RSA_PUBKEY()로 생성하는 경우
        - "-----BEGIN RSA PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----"
          - PEM_write_bio_RSAPublicKey()로 생성하는 경우
        - "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"
          - PEM_write_bio_RSAPrivateKey()로 생성
      - 64글자마다 줄바꿈(\n)이 추가된다.
   * CER, CRT: 인증서 파일. X509 포맷이며 public key, 시작일, 만료일등이 포함되어 있다.
   * P12: PCKS12 포맷이며 private key 정보가 들어있다.
      - rsa private key 안에는 rsa public key를 포함하고 있다.
