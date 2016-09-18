/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.etfbl.cryptodigitalcertificate.tool;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import net.etfbl.cryptodigitalcertificate.CryptoDigitalCertificate;
import net.etfbl.cryptodigitalcertificate.tool.util.CryptoPEMExtractor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 *
 * @author ZM
 */
public class CryptoDCTool {

    private static final String DEFAULT_COUNTRY  = "BA";
    private static final String DEFAULT_STATE    = "RS";
    private static final String DEFAULT_LOCALITY = "Banja Luka";
    private static final String DEFAULT_ORGANIZATION = "etf";
    private static final String DEFAULT_ORG_UNIT = "etf";
    private static final String DEFAULT_COMMON_NAME = "";
    private static final String DEFAULT_EMAIL = "default@mail.com";
    
    private static final String DEFAULT_KEYSTORE_ALIAS = "Private Key";
    private static final int DEFAULT_NUMBER_OF_DAYS = 365;
    
    private String command;
    private String inputFile;
    private String outputFile;
    private String clientKeysFile;

    public String getClientKeysFile() {
        return clientKeysFile;
    }

    public void setClientKeysFile(String clientKeysFile) {
        this.clientKeysFile = clientKeysFile;
    }

    public String getOutputFile() {
        return outputFile;
    }

    public void setOutputFile(String outputFile) {
        this.outputFile = outputFile;
    }
    private String keyLenght;

    public String getInputFile() {
        return inputFile;
    }

    public void setInputFile(String inputFile) {
        this.inputFile = inputFile;
    }

    public String getKeyLenght() {
        return keyLenght;
    }

    public void setKeyLenght(String keyLenght) {
        this.keyLenght = keyLenght;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public void executeCommand() {
        switch (command) {
            case "genrsa": {
                generateRSA();
                break;
            }
            case "req": {
                createRequest();
                break;
            }
            case "pkcs12": {
                signCSR();
                break;
            }
            case "--help": {
                displayHelp();
                break;
            }
            default: {
                System.out.println("Invalid command " + command);
                break;
            }
        }
    }

    private void generateRSA() {
        assertParameter(keyLenght, "-key");
        assertParameter(outputFile, "-out");
        try {
            int keyLength = Integer.parseInt(keyLenght);
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyGenerator.initialize(keyLength);
            KeyPair key = keyGenerator.generateKeyPair();
            new CryptoPEMExtractor().writeObject(key, outputFile);
            System.out.println("\nGenerated key (" + keyLenght + " bits): " + outputFile);

        } catch (NumberFormatException | NoSuchAlgorithmException |
                NoSuchProviderException | FileNotFoundException ex) {
            System.out.println(ex.getMessage());
        }catch(IOException ex){
            System.out.println(ex.getMessage());
        }
    }

    private void createRequest() {
        assertParameter(inputFile, "-in");
        assertParameter(outputFile, "-out");
        try {
            String country      = RequestFromUser("Country name (2 letter code) [" + "BA" + "]:", DEFAULT_COUNTRY);
            String state        = RequestFromUser("State or Province Name (full name) [" + DEFAULT_STATE + "]:", DEFAULT_STATE);
            String locality     = RequestFromUser("Locality Name (eg, city) ["+ DEFAULT_LOCALITY + "]:", DEFAULT_LOCALITY);
            String organization = RequestFromUser("Organization Name (eg, company) [" + DEFAULT_ORGANIZATION + "]:", DEFAULT_ORGANIZATION);
            String unit         = RequestFromUser("Organizational Unit Name (eg, section) [" + DEFAULT_ORG_UNIT + "]:", DEFAULT_ORG_UNIT);
            String common       = RequestFromUser("Common Name (e.g. server FQDN or Your name) [" + DEFAULT_COMMON_NAME + "]:", DEFAULT_COMMON_NAME);
            String email        = RequestFromUser("Email Address [" + DEFAULT_EMAIL + "]:", DEFAULT_EMAIL);
            //TO DO - Check the data
            X500Principal subject = new X500Principal("C=" + country + ", "
                    + "ST=" + state + ", "
                    + "L=" + locality + ", "
                    + "O=" + organization + ", "
                    + "OU= " + unit + ", "
                    + "CN=" + common + ", "
                    + "EMAILADDRESS=" + email);

            CryptoPEMExtractor exctractor = new CryptoPEMExtractor();
            KeyPair pair = exctractor.loadKeyPair(inputFile);
            if (pair != null) {
                PrivateKey key = pair.getPrivate();
                PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
                String signAlgorythm = "SHA256withRSA";
                ContentSigner signGen = new JcaContentSignerBuilder(signAlgorythm).build(key);
                PKCS10CertificationRequest request = builder.build(signGen);
                exctractor.writeObject(request, outputFile);

                System.out.println("\nGenerated certificate request: " + outputFile);

            } else {
                System.out.println("Failed to load key pair from file " + inputFile);
            }
        } catch (OperatorCreationException | IOException ex) {
            System.out.println(ex.getMessage());
        }

    }

    public void signCSR() {
        assertParameter(inputFile, "-in");
        assertParameter(clientKeysFile, "-keys");
        assertParameter(outputFile, "-out");
        try {
            CryptoPEMExtractor exctractor = new CryptoPEMExtractor();
            //Load CA keys and CA certificate
            KeyPair caKeys = exctractor.loadKeyPair(this.getClass().getResourceAsStream("/keys/caprivate.key"));
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            X509Certificate cacert = (X509Certificate) fact.generateCertificate(this.getClass().getResourceAsStream("/certs/cacert.pem"));
            //Load certificate request
            PKCS10CertificationRequest request = (PKCS10CertificationRequest) exctractor.loadObject(inputFile);
            //Setup X509 certificate generator with specified certificate data
            X509v3CertificateBuilder certgen = setupCertificateData(cacert, request);
            ContentSigner signer = setupHashAndSignAlgorythm(caKeys);
            //Create certificate
            X509CertificateHolder holder = certgen.build(signer);
            X509Certificate clientCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            //Generate password
            String exportPassword = java.util.UUID.randomUUID().toString().substring(0, 4);
            //Save certificate in keystore
            storeCertificateInKeyStore(cacert, clientCert, exportPassword);

            System.out.println("\nGenerated PKCS#12 file. Password is: " + exportPassword);

        } catch (CertificateException | OperatorCreationException | KeyStoreException |
                NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException |
                SignatureException | IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    private void displayHelp() {
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                CryptoDigitalCertificate.class.getResourceAsStream("/doc/help.txt")));
        String line = "";
        try {
            System.out.println();
            while((line = reader.readLine()) != null){
                System.out.println(line);
            }
            reader.close();
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
    
    private String RequestFromUser(String message, String defaultValue) {
        System.out.print(message);
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        if (input == null || "".equals(input)) {
            input = defaultValue;
        }
        return input;
    }

    private X509v3CertificateBuilder setupCertificateData(X509Certificate cacert, PKCS10CertificationRequest request) throws CertIOException {
        X500Name issuer = new X500Name(cacert.getSubjectX500Principal().getName());
        BigInteger serial = new BigInteger(32, new SecureRandom());
        Date from = new Date();
        Date to = new Date(System.currentTimeMillis() + (DEFAULT_NUMBER_OF_DAYS * 86400000L));
        X509v3CertificateBuilder certgen = new X509v3CertificateBuilder(issuer,
                serial,
                from,
                to,
                request.getSubject(),
                request.getSubjectPublicKeyInfo());
        //
        //  Setup the certificate extensions
        //
        // Basic Constraints
        certgen.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        // Authority Key Identifier
        SubjectPublicKeyInfo caSubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(cacert.getPublicKey().getEncoded());
        // Key Usage
        certgen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.keyEncipherment));

        return certgen;
    }

    private ContentSigner setupHashAndSignAlgorythm(KeyPair caKeys) throws IOException, OperatorCreationException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        return new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                .build(PrivateKeyFactory.createKey(caKeys.getPrivate().getEncoded()));
    }

    private void storeCertificateInKeyStore(X509Certificate cacert, X509Certificate clientCert, String exportPassword) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, KeyStoreException {
        CryptoPEMExtractor exctractor = new CryptoPEMExtractor();
        KeyPair clientPair = exctractor.loadKeyPair(clientKeysFile);
        clientCert.verify(cacert.getPublicKey());
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = clientCert;
        store.setKeyEntry(DEFAULT_KEYSTORE_ALIAS, clientPair.getPrivate(), exportPassword.toCharArray(), chain);
        FileOutputStream fOut = new FileOutputStream(outputFile);
        store.store(fOut, exportPassword.toCharArray());
    }
    
    private void assertParameter(String parameter, String name){
        if(parameter == null){
            System.out.println("Parameter " + name + " not specified. Use --help for more information.");
            System.exit(1);
        }
    }
}
