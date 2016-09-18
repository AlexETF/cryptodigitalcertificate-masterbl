/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.etfbl.cryptodigitalcertificate.tool.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 *
 * @author ZM
 */
public class CryptoPEMExtractor {

    public void writeObject(Object object, String filePath) throws FileNotFoundException, IOException {
        JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(filePath)));
        try {
            writer.writeObject(object);
        } finally {
            writer.close();
        }
    }

    public Object loadObject(String filePath) throws FileNotFoundException, IOException {
        PEMParser reader = new PEMParser(new InputStreamReader(new FileInputStream(filePath)));
        Object keyObject = reader.readObject();
        reader.close();
        return keyObject;
    }

    public Object loadObject(InputStream stream) throws FileNotFoundException, IOException {
        PEMParser reader = new PEMParser(new InputStreamReader(stream));
        Object keyObject = reader.readObject();
        reader.close();
        return keyObject;
    }

    public KeyPair loadKeyPair(String filePath) throws FileNotFoundException, IOException {
        PEMParser reader = new PEMParser(new InputStreamReader(new FileInputStream(filePath)));
        Object keyObject = reader.readObject();
        reader.close();
        PEMKeyPair pemPair = (PEMKeyPair) keyObject;
        KeyPair pair = new JcaPEMKeyConverter().getKeyPair(pemPair);
        return pair;
    }

    public KeyPair loadKeyPair(InputStream stream) throws FileNotFoundException, IOException {
        PEMParser reader = new PEMParser(new InputStreamReader(stream));
        Object keyObject = reader.readObject();
        reader.close();
        PEMKeyPair pemPair = (PEMKeyPair) keyObject;
        KeyPair pair = new JcaPEMKeyConverter().getKeyPair(pemPair);
        return pair;
    }

    public void writeKey(Key key, String filePath) throws FileNotFoundException, IOException {
        PemWriter writer = new PemWriter(new OutputStreamWriter(new FileOutputStream(filePath)));
        try {
            writer.writeObject(new PemObject("RSA private key", key.getEncoded()));
        } finally {
            writer.close();
        }

    }

    public Key loadKey(String filePath, boolean pubKey) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Key key = null;
        PemReader reader = new PemReader(new InputStreamReader(new FileInputStream(filePath)));
        PemObject keyObject = reader.readPemObject();
        reader.close();
        if (pubKey) {
            key = KeyFactory.getInstance("RSA").
                    generatePublic(new X509EncodedKeySpec(keyObject.getContent()));
        } else {
            key = KeyFactory.getInstance("RSA").
                    generatePrivate(new PKCS8EncodedKeySpec(keyObject.getContent()));
        }
        return key;
    }
}
