# Get-CapiTaskIDEvents
In the CAPI2 Log there is sometimes the need to output all CAPI2 events in sequence that are written from a specific application or process. This function and its helper function can be used to filter those Events based on the TaskID  

PARAMETER <b>TaskID</b><br />
'This mandatory TaskID must be obtained from one sequece of the events'
<details>
<summary>     
EXAMPLES
</summary>
Get-CapiTaskIDEvents -TaskID "7E11B6A3-50EA-47ED-928D-BBE4784EFA3F" | Format-List

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 10
        RecordType      : Informationen
        DetailedMessage : <CertGetCertificateChainStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="1"
                          /></CertGetCertificateChainStart>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 40
        RecordType      : Informationen
        DetailedMessage : <CertVerifyRevocationStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="2"
                          /></CertVerifyRevocationStart>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 41
        RecordType      : Informationen
        DetailedMessage : <CertVerifyRevocation xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01" /><IssuerCertificate       
                          fileRef="D4DE20D05E66FC53FE1A50882C78DB2852CAE474.cer" subjectName="Baltimore CyberTrust Root" /><Flags value="2"       
                          CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION="true" /><AdditionalParameters timeToUse="2022-10-25T13:48:50.075Z"
                          currentTime="2022-10-25T13:48:50.075Z" urlRetrievalTimeout="PT15S" /><RevocationStatus index="0" error="0" reason="0"   
                          actualFreshnessTime="PT9H33M48S" thirdPartyProviderUsed="C:\Windows\System32\cryptnet.dll" /><OCSPResponse
                          location="TvoCache" fileRef="D3B95EBB9474B2AC60FEE68BF670ACCF0168CEDE.bin" issuerName="Baltimore CyberTrust Root"       
                          /><EventAuxInfo ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}"
                          SeqNumber="3" /><Result value="0" /></CertVerifyRevocation>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 40
        RecordType      : Informationen
        DetailedMessage : <CertVerifyRevocationStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="4"
                          /></CertVerifyRevocationStart>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 50
        RecordType      : Informationen
        DetailedMessage : <CryptRetrieveObjectByUrlCacheStart xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventAuxInfo
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="5"
                          /></CryptRetrieveObjectByUrlCacheStart>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 51
        RecordType      : Informationen
        DetailedMessage : <CryptRetrieveObjectByUrlCache xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><URL
                          scheme="http">http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20RSA%20TLS%20CA%2001.crl</URL><Object
                          type="CONTEXT_OID_CRL" constant="2" /><Flags value="2003" CRYPT_RETRIEVE_MULTIPLE_OBJECTS="true"
                          CRYPT_CACHE_ONLY_RETRIEVAL="true" CRYPT_LDAP_SCOPE_BASE_ONLY_RETRIEVAL="true" /><AuxInfo
                          maxUrlRetrievalByteCount="104857600" /><CacheInfo lastSyncTime="2022-10-11T17:26:56.434Z"><URLCachePrefetchInfo
                          objectType="CRYPTNET_URL_CACHE_PRE_FETCH_CRL" error="10D0" thisUpdateTime="2022-10-10T21:49:58Z"
                          nextUpdateTime="2022-10-18T22:09:58Z" publishTime="2022-10-14T21:59:58Z" /><URLCacheFlushInfo
                          expireTime="2022-10-18T22:09:58Z" /><URLCacheResponseInfo responseType="CRYPTNET_URL_CACHE_RESPONSE_HTTP"
                          responseValidated="true" lastModifiedTime="2022-10-10T22:00:15Z"
                          /></CacheInfo><RetrievedObjects><CertificateRevocationList fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl"       
                          issuerName="Microsoft RSA TLS CA 01" /></RetrievedObjects><EventAuxInfo ProcessName="msedge.exe" /><CorrelationAuxInfo  
                          TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="6" /><Result value="0" /></CryptRetrieveObjectByUrlCache>    

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 42
        RecordType      : Fehler
        DetailedMessage : <CertRejectedRevocationInfo xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><SubjectCertificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><IssuerCertificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01"
                          /><CertificateRevocationList location="UrlCache"
                          url="http://mscrl.microsoft.com/pki/mscorp/crl/Microsoft%20RSA%20TLS%20CA%2001.crl"
                          fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl" issuerName="Microsoft RSA TLS CA 01" /><Action
                          name="CheckTimeValidity" /><EventAuxInfo ProcessName="msedge.exe" /><CorrelationAuxInfo
                          TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="7" /></CertRejectedRevocationInfo>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 41
        RecordType      : Fehler
        DetailedMessage : <CertVerifyRevocation xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><IssuerCertificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01" /><Flags value="2"
                          CERT_VERIFY_CACHE_ONLY_BASED_REVOCATION="true" /><AdditionalParameters timeToUse="2022-10-25T13:48:50.075Z"
                          currentTime="2022-10-25T13:48:50.075Z" urlRetrievalTimeout="PT15S" /><RevocationStatus index="0" error="80092013"       
                          reason="0" actualFreshnessTime="P14DT15H58M52S" thirdPartyProviderUsed="C:\Windows\System32\cryptnet.dll"
                          /><CertificateRevocationList location="TvoCache" fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl"
                          issuerName="Microsoft RSA TLS CA 01" /><EventAuxInfo ProcessName="msedge.exe" /><CorrelationAuxInfo
                          TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="8" /><Result value="80092013">Die Sperrfunktion konnte die   
                          Sperrung nicht überprüfen, da der Sperrserver offline war.</Result></CertVerifyRevocation>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 90
        RecordType      : Informationen
        DetailedMessage : <X509Objects xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01"><Subject><CN>Microsoft     
                          RSA TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Subject><SubjectKeyID computed="false"
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"     
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="4096"
                          /><Issuer><CN>Baltimore CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><SerialNumber>0F14965F 
                          202069994FD5C7AC788941E2</SerialNumber><NotBefore>2020-07-21T23:00:00Z</NotBefore><NotAfter>2024-10-08T07:00:00Z</NotAf 
                          ter><Extensions><AuthorityKeyIdentifier><KeyID hash="E59D5930824758CCACFA085436867B3AB5044DF0"
                          /></AuthorityKeyIdentifier><KeyUsage critical="true" value="86" CERT_DIGITAL_SIGNATURE_KEY_USAGE="true"
                          CERT_KEY_CERT_SIGN_KEY_USAGE="true" CERT_CRL_SIGN_KEY_USAGE="true" /><ExtendedKeyUsage><Usage oid="1.3.6.1.5.5.7.3.1"   
                          name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" 
                          /></ExtendedKeyUsage><BasicConstraints critical="true" cA="true" pathLenConstraint="0" /><CertificatePolicies><Policy   
                          oid="2.23.140.1.2.1" /><Policy oid="2.23.140.1.2.2" /><Policy oid="1.3.6.1.4.1.311.42.1"
                          /></CertificatePolicies></Extensions></Certificate><Certificate fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer"  
                          subjectName="r.bing.com"><Subject><CN>r.bing.com</CN><O>Microsoft
                          Corporation</O><L>Redmond</L><S>WA</S><C>US</C></Subject><SubjectKeyID computed="false"
                          hash="F6CB10F1E887FD3C75E0CCB02C76B7DBA56A0517" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"     
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="2048"
                          /><Issuer><CN>Microsoft RSA TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Issuer><SerialNumber>12001EA96F3C9E29F 
                          709C4E56D0000001EA96F</SerialNumber><NotBefore>2021-12-07T20:58:22Z</NotBefore><NotAfter>2022-12-07T20:58:22Z</NotAfter 
                          ><Extensions><KeyUsage critical="true" value="B0" CERT_DIGITAL_SIGNATURE_KEY_USAGE="true"
                          CERT_KEY_ENCIPHERMENT_KEY_USAGE="true" CERT_DATA_ENCIPHERMENT_KEY_USAGE="true" /><SubjectAltName><DNSName>r.bing.com</D 
                          NSName><DNSName>thaka.msftstatic.com</DNSName><DNSName>thaka.bing.com</DNSName><DNSName>th.msftstatic.com</DNSName><DNS 
                          Name>th.bing.com</DNSName><DNSName>raka.msftstatic.com</DNSName><DNSName>raka.bing.com</DNSName><DNSName>r.msftstatic.c 
                          om</DNSName><DNSName>akam.bing.com</DNSName><DNSName>*.mm.bing.net</DNSName><DNSName>*.explicit.bing.net</DNSName><DNSN 
                          ame>*.bingstatic.com</DNSName><DNSName>*.bing.com</DNSName></SubjectAltName><CertificatePolicies><Policy
                          oid="1.3.6.1.4.1.311.42.1" /><Policy oid="2.23.140.1.2.2" /></CertificatePolicies><AuthorityKeyIdentifier><KeyID        
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /></AuthorityKeyIdentifier><ExtendedKeyUsage><Usage
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung"  
                          /></ExtendedKeyUsage></Extensions></Certificate><OCSPResponse fileRef="D3B95EBB9474B2AC60FEE68BF670ACCF0168CEDE.bin"    
                          issuerName="Baltimore CyberTrust Root"><Status
                          value="0">OCSP_SUCCESSFUL_RESPONSE</Status><ProducedAt>2022-10-25T04:31:18Z</ProducedAt><Issuer><CN>Baltimore
                          CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><DelegatedSigner><CN>Baltimore Cybertrust      
                          Validation 2025</CN><O>DigiCert,
                          Inc.</O><C>US</C></DelegatedSigner><Response><SerialNumber>0F14965F202069994FD5C7AC788941E2</SerialNumber><CertStatus v 
                          alue="0">OCSP_BASIC_GOOD_CERT_STATUS</CertStatus><ThisUpdate>2022-10-25T04:15:02Z</ThisUpdate><NextUpdate>2022-11-01T03 
                          :30:02Z</NextUpdate></Response></OCSPResponse><Certificate fileRef="D4DE20D05E66FC53FE1A50882C78DB2852CAE474.cer"       
                          subjectName="Baltimore CyberTrust Root"><Subject><CN>Baltimore CyberTrust
                          Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Subject><SubjectKeyID computed="false"
                          hash="E59D5930824758CCACFA085436867B3AB5044DF0" /><SignatureAlgorithm oid="1.2.840.113549.1.1.5" hashName="SHA1"        
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="2048"
                          /><Issuer><CN>Baltimore CyberTrust Root</CN><OU>CyberTrust</OU><O>Baltimore</O><C>IE</C></Issuer><SerialNumber>020000B9 
                          </SerialNumber><NotBefore>2000-05-12T18:46:00Z</NotBefore><NotAfter>2025-05-12T23:59:00Z</NotAfter><Extensions><BasicCo 
                          nstraints critical="true" cA="true" pathLenConstraint="3" /><KeyUsage critical="true" value="06"
                          CERT_KEY_CERT_SIGN_KEY_USAGE="true" CERT_CRL_SIGN_KEY_USAGE="true" /></Extensions><Properties><ExtendedKeyUsage><Usage  
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.3" name="Codesignatur" /><Usage    
                          oid="1.3.6.1.5.5.7.3.4" name="Sichere E-Mail" /><Usage oid="1.3.6.1.5.5.7.3.9" name="OCSP-Signatur" /><Usage
                          oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.8" name="Zeitstempel"
                          /></ExtendedKeyUsage><FriendlyName>DigiCert Baltimore Root</FriendlyName><PoliciesInfo><PolicyInfo
                          certPolicyId="1.3.6.1.4.1.6334.1.100.1"><RootProgramPolicyQualifierInfo
                          policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true"
                          CERT_ROOT_PROGRAM_FLAG_LSC="true" /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.16.840.1.114412.2.1"><RootProgramPolicyQualifierInfo
                          policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true"
                          CERT_ROOT_PROGRAM_FLAG_LSC="true" /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.23.140.1.1"><RootProgramPolicyQualifierInfo policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers      
                          value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true" CERT_ROOT_PROGRAM_FLAG_LSC="true"
                          /></RootProgramPolicyQualifierInfo></PolicyInfo><PolicyInfo
                          certPolicyId="2.23.140.1.3"><RootProgramPolicyQualifierInfo policyQualifierId="1.3.6.1.4.1.311.60.1.1"><Qualifiers      
                          value="C0" CERT_ROOT_PROGRAM_FLAG_ORG="true" CERT_ROOT_PROGRAM_FLAG_LSC="true"
                          /></RootProgramPolicyQualifierInfo></PolicyInfo></PoliciesInfo></Properties></Certificate><CertificateRevocationList    
                          fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl" issuerName="Microsoft RSA TLS CA 01"><Issuer><CN>Microsoft RSA   
                          TLS CA 01</CN><O>Microsoft Corporation</O><C>US</C></Issuer><ThisUpdate>2022-10-10T21:49:58Z</ThisUpdate><NextUpdate>20 
                          22-10-18T22:09:58Z</NextUpdate><Extensions><AuthorityKeyIdentifier><KeyID
                          hash="B5760C3011CEC792424D4CC75C2CC8A90CE80B64" /></AuthorityKeyIdentifier><CRLNumber>010D</CRLNumber><NextPublishTime> 
                          2022-10-14T21:59:58Z</NextPublishTime></Extensions></CertificateRevocationList><EventAuxInfo ProcessName="msedge.exe"   
                          /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="9" /></X509Objects>

        TimeCreated     : 10/25/2022 3:48:50 PM
        ID              : 11
        RecordType      : Fehler
        DetailedMessage : <CertGetCertificateChain xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><AdditionalStore><Certificate
                          fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer" subjectName="Microsoft RSA TLS CA 01" /><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /></AdditionalStore><ExtendedKeyUsage   
                          orMatch="true"><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage oid="1.3.6.1.4.1.311.10.3.3"      
                          /><Usage oid="2.16.840.1.113730.4.1" /></ExtendedKeyUsage><StrongSignPara
                          signHashList="RSA/SHA256;RSA/SHA384;RSA/SHA512;ECDSA/SHA256;ECDSA/SHA384;ECDSA/SHA512"
                          publicKeyList="RSA/1024;ECDSA/256" /><Flags value="A0000000" CERT_CHAIN_REVOCATION_CHECK_CHAIN="true"
                          CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY="true" /><ChainEngineInfo context="user" /><CertificateChain
                          chainRef="{0329F7C5-3224-41B2-ACF9-A79196D86FF8}"><TrustStatus><ErrorStatus value="1000040"
                          CERT_TRUST_REVOCATION_STATUS_UNKNOWN="true" CERT_TRUST_IS_OFFLINE_REVOCATION="true" /><InfoStatus value="100"
                          CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ChainElement><Certificate
                          fileRef="930F5167FA5112F077FC65AB3DFFE8A347F5BD9B.cer" subjectName="r.bing.com" /><SignatureAlgorithm
                          oid="1.2.840.113549.1.1.11" hashName="SHA256" publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1"      
                          publicKeyName="RSA" publicKeyLength="2048" /><TrustStatus><ErrorStatus value="1000040"
                          CERT_TRUST_REVOCATION_STATUS_UNKNOWN="true" CERT_TRUST_IS_OFFLINE_REVOCATION="true" /><InfoStatus value="102"
                          CERT_TRUST_HAS_KEY_MATCH_ISSUER="true" CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ApplicationUsage><Usage  
                          oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung"  
                          /></ApplicationUsage><IssuanceUsage><Usage oid="2.23.140.1.2.2" /><Usage oid="1.3.6.1.4.1.311.42.1"
                          /></IssuanceUsage><RevocationInfo freshnessTime="P14DT15H58M52S"><RevocationResult value="80092013">Die Sperrfunktion   
                          konnte die Sperrung nicht überprüfen, da der Sperrserver offline war.</RevocationResult><StrongSignProperties
                          signHash="RSA/SHA256" issuerPublicKeyLength="4096" /><CertificateRevocationList location="TvoCache"
                          fileRef="44649D4C2634C2B5BD91AB9E0A70C5EAFC8B864A.crl" issuerName="Microsoft RSA TLS CA 01"
                          /></RevocationInfo></ChainElement><ChainElement><Certificate fileRef="703D7A8F0EBF55AAA59F98EAF4A206004EB2516A.cer"     
                          subjectName="Microsoft RSA TLS CA 01" /><SignatureAlgorithm oid="1.2.840.113549.1.1.11" hashName="SHA256"
                          publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1" publicKeyName="RSA" publicKeyLength="4096"
                          /><TrustStatus><ErrorStatus value="0" /><InfoStatus value="102" CERT_TRUST_HAS_KEY_MATCH_ISSUER="true"
                          CERT_TRUST_HAS_PREFERRED_ISSUER="true" /></TrustStatus><ApplicationUsage><Usage oid="1.3.6.1.5.5.7.3.1"
                          name="Serverauthentifizierung" /><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung"
                          /></ApplicationUsage><IssuanceUsage><Usage oid="2.23.140.1.2.1" /><Usage oid="2.23.140.1.2.2" /><Usage
                          oid="1.3.6.1.4.1.311.42.1" /></IssuanceUsage><RevocationInfo freshnessTime="PT9H33M48S"><RevocationResult value="0"     
                          /><StrongSignProperties signHash="RSA/SHA256" issuerPublicKeyLength="2048" issuerSignHashList="RSA/SHA256"
                          /><OCSPResponse location="TvoCache" fileRef="D3B95EBB9474B2AC60FEE68BF670ACCF0168CEDE.bin" issuerName="Baltimore        
                          CyberTrust Root" /></RevocationInfo></ChainElement><ChainElement><Certificate
                          fileRef="D4DE20D05E66FC53FE1A50882C78DB2852CAE474.cer" subjectName="Baltimore CyberTrust Root" /><SignatureAlgorithm    
                          oid="1.2.840.113549.1.1.5" hashName="SHA1" publicKeyName="RSA" /><PublicKeyAlgorithm oid="1.2.840.113549.1.1.1"
                          publicKeyName="RSA" publicKeyLength="2048" /><TrustStatus><ErrorStatus value="0" /><InfoStatus value="10C"
                          CERT_TRUST_HAS_NAME_MATCH_ISSUER="true" CERT_TRUST_IS_SELF_SIGNED="true" CERT_TRUST_HAS_PREFERRED_ISSUER="true"
                          /></TrustStatus><ApplicationUsage><Usage oid="1.3.6.1.5.5.7.3.2" name="Clientauthentifizierung" /><Usage
                          oid="1.3.6.1.5.5.7.3.3" name="Codesignatur" /><Usage oid="1.3.6.1.5.5.7.3.4" name="Sichere E-Mail" /><Usage
                          oid="1.3.6.1.5.5.7.3.9" name="OCSP-Signatur" /><Usage oid="1.3.6.1.5.5.7.3.1" name="Serverauthentifizierung" /><Usage   
                          oid="1.3.6.1.5.5.7.3.8" name="Zeitstempel" /></ApplicationUsage><IssuanceUsage any="true"
                          /><RevocationInfo><RevocationResult value="0" /></RevocationInfo></ChainElement></CertificateChain><EventAuxInfo        
                          ProcessName="msedge.exe" /><CorrelationAuxInfo TaskId="{7E11B6A3-50EA-47ED-928D-BBE4784EFA3F}" SeqNumber="10"
                          /><Result value="80092013">Die Sperrfunktion konnte die Sperrung nicht überprüfen, da der Sperrserver offline
                          war.</Result></CertGetCertificateChain>

</details>
