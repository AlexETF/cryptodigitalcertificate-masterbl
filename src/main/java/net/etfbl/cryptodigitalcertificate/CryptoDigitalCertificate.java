/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.etfbl.cryptodigitalcertificate;

import net.etfbl.cryptodigitalcertificate.tool.CryptoDCTool;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author ZM
 */
public class CryptoDigitalCertificate {

    private static CryptoDCTool tool = new CryptoDCTool();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    public static void main(String[] args) {
        if(processCommandLineArgs(args)){
            tool.executeCommand();
        }
    }

    private static boolean processCommandLineArgs(String[] args) {
        if (args.length == 0) {
            System.out.println("ERROR: Not enough arguments. Use --help for more information.");
            return false;
        }
        tool.setCommand(args[0]);
        try {
            for (int i = 1; i < args.length - 1; i += 2) {
                switch (args[i]) {
                    case "-in": {
                        tool.setInputFile(args[i + 1]);
                        break;
                    }
                    case "-out": {
                        tool.setOutputFile(args[i + 1]);
                        break;
                    }
                    case "-key":{
                        tool.setKeyLenght(args[i + 1]);
                        break;
                    }
                    case "-keys":{
                        tool.setClientKeysFile(args[i + 1]);
                        break;
                    }
                    default: {
                        System.out.println("ERROR: Invalid argument " + args[i] + " passed ");
                        return false;
                    }
                }
            }
            return true;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return false;
    }
}
