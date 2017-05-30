## DER

* openssl 명령 프롬프트에서 파일 내용 확인하기
```bash
$ openssl rsa -in publickey.der -inform DER -text -pubin
$ openssl rsa -in privatekey.der -inform DER -text
```

* 명령 프롬프트에서 파싱하기
```bash
$ openssl asn1parse -inform DER -in publickey.der -offset 24 -dump
```

* 포맷
  - tag(1byte): asn1.h 파일의 V_ASN1_* 에 정의 되어 있음.
  - length(1~3byte)
    - 1byte가 0x81 보다 작은 경우: 첫번째 byte가 data의 길이
    - 1byte가 0x81 인 경우: 두번째 byte가 data의 길이
    - 1byte가 0x81 보다 큰 경우: 두번째 세번째 byte가 data의 길이
  - data

* 파싱 예제
  - 2048 bit RSA 구조체에서 i2d_RSAPublicKey()로 추출한 경우 DER 형식 (270byte)
      - 파싱 내용
        - 30: SEQUENCE
            - 82010A: length 266
            - 02: INTEGER
                - 820101: length 257
                - 00: public key(256byte) 앞에 0x00을 추가해서 257 byte가 된다.
                - DD6F~2511: public key
            - 02: INTEGER
                - 03: length 3
                - 010001: exponent 값 (65,537)
      - 데이터
        ```text
        3082010A0282010100DD6FB9D396BC32DBC7A8247AE7ABB34D7351F569889DFCD5303CF8748CC87ACC3248B0ABF426FF5F9C6723763BD8E862ED09DBACD48FC68AA251ED020EE4C60ACBDDDE7204237D924E7525AF66425F9F8E5022C5E040E03840DB711F813F50BECD81E2389A8E7B4E625849514C20330B101CA2F40EE04D7515092D22EA64808E6712671180F6A122F5E9ECBD10190DB2A361FED4F54D12DBC8FAA0EFB69CA68699F6354593660428D8706D39F20D2C032391D3894A50FAED07398C0D697A59B43ED17541E148D4BD636F10D0E35080D3239FE810A0E1237DFAE388F3483D00D228A28D8F933E1B6DDCC206CD75C5F3CF57EDBEA595FEE61B74F2C15A3C9225110203010001
        ```
  - 2048 bit RSA 인증서에서 명령프롬프트로 추출한 DER (294byte)
      - 파싱 내용
        - 30: SEQUENCE
            - 820122: length 290
	        - 30: SEQUENCE
	            - 0D: length 13
	            - 06: OBJECT
	                - 09: length 9
                    - 2A864886F70D010101: rsaEncryption
                - 0500: NULL
	            - 03: BIT STRING
	                - 82010F: length 271
	                - 00: NULL
	                - 30: SEQUENCE
	                    - 82010A: length 266
                        - 02: INTEGER
                            - 820101: length 257
                            - 00: public key(256byte) 앞에 0x00을 추가해서 257 byte가 된다.
                            - DD6F~2511: public key
                        - 02: INTEGER
                            - 03: length 3
                            - 010001: exponent 값 (65,537)
      - 데이터
        ```text
            30820122300D06092A864886F70D01010105000382010F003082010A0282010100DD6FB9D396BC32DBC7A8247AE7ABB34D7351F569889DFCD5303CF8748CC87ACC3248B0ABF426FF5F9C6723763BD8E862ED09DBACD48FC68AA251ED020EE4C60ACBDDDE7204237D924E7525AF66425F9F8E5022C5E040E03840DB711F813F50BECD81E2389A8E7B4E625849514C20330B101CA2F40EE04D7515092D22EA64808E6712671180F6A122F5E9ECBD10190DB2A361FED4F54D12DBC8FAA0EFB69CA68699F6354593660428D8706D39F20D2C032391D3894A50FAED07398C0D697A59B43ED17541E148D4BD636F10D0E35080D3239FE810A0E1237DFAE388F3483D00D228A28D8F933E1B6DDCC206CD75C5F3CF57EDBEA595FEE61B74F2C15A3C9225110203010001
        ```
