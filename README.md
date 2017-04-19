# OpenSSL

## OpenSSL 명령행 사용법

### RSA
  - Private key 와 인증서 생성
    > openssl req -x509 -sha1 -nodes -days 1826 -newkey rsa:2048 -keyout rsaprivkey.pem -out ca.crt
  - 키 검증
    > openssl x509 -in ca.crt -text -noout
    > openssl rsa -in rsaprivkey.pem -check
  - Private key pkcs12 형식으로 변환
    > openssl pkcs12 -export -nocerts -inkey rsaprivkey.pem -out rsaprivkey.p12
  - Private key pkcs12 검증
    > openssl pkcs12 -info -in rsaprivkey.p12

### DSA
  - 키 파라미터 생성
    > openssl dsaparam -out dsaparam.pem 2048
  - Private key 생성
    > openssl gendsa -out dsaprivkey.pem dsaparam.pem
  - Private key 검증
    > openssl dsa -in dsaprivkey.pem -inform pem
  - Private key der 형식으로 변환
    > openssl pkcs8 -topk8 -inform PEM -outform DER -in dsaprivkey.pem -out dsaprivkey.der -nocrypt
  - Private key der 검증
    > openssl dsa -in dsaprivkey.der -inform der
  - Pubilc key 생성
    > openssl dsa -in dsaprivkey.pem -outform DER -pubout -out dsapubkey.der
  - Pubilc key 검증 
    > openssl dsa -pubin -in dsapubkey.der -inform der
