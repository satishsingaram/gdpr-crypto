package com.bingo.oms.crypto.crypto;

import com.bingo.oms.crypto.crypto.util.FileUtil;
import com.bingo.oms.crypto.crypto.util.GPGUtil;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Properties;

public class GPGService {

    private Properties props;

    /**
     * Logger instance.
     */
    //private static Logger log = new Logger(GPGService.class);

    /*
     * Initializing logging and api object
     */

    //private static YFCLogCategory oBaseLog = YFCLogCategory.instance(GPGService.class.getName());
    public Properties getProps() {
        return props;
    }

    public void setProperties(Properties prop) throws Exception {
        this.props = prop;

    }

    public final Document processCrypto(Document inDoc) throws Exception {

        logDebugInfo("processCrypto Begin: Input to processCrypto Method is :: " + FileUtil.getXMLString(inDoc));
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Document outDoc = null;
        String strCryptoMethod = (String) props.get(CryptoConstant.CRYPTO_METHOD);
        if (strCryptoMethod != null && strCryptoMethod.equals(CryptoConstant.CRYPTO_DECRYPT)) {
            logDebugInfo("Process Decrypt ");
            outDoc = processDecrypt(inDoc);
        } else if (strCryptoMethod != null && strCryptoMethod.equals(CryptoConstant.CRYPTO_ENCRYPT)) {
            logDebugInfo("Process Encrypt ");
            outDoc = processEncrypt(inDoc);
        }
        logDebugInfo("outDoc = " + outDoc);
        return outDoc;
    }

    public final String processCryptoString(String strInDoc, String strCryptoMethod, String strPropFilePath, String strPass) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        logDebugInfo("processCryptoString Begin: Input to processCryptoString Method is :: " + strInDoc);
        String outStr = null;
        Properties prop = FileUtil.loadProjectProperties(strPropFilePath);
        logDebugInfo("strPropFilePath = " + strPropFilePath + "strInDoc = " + strInDoc);
        String strPubKey = prop.getProperty(CryptoConstant.PUB_KEY_PATH);
        String strPrivateKey = prop.getProperty(CryptoConstant.SEC_KEY_PATH);
        logDebugInfo("strPubKey = " + strPubKey + " strSecKey = " + strPrivateKey);
        logDebugInfo("Before strCryptoMethod condition");
        if (strCryptoMethod != null && strCryptoMethod.equals(CryptoConstant.CRYPTO_DECRYPT)) {
            logDebugInfo("inside if without Null for Decrypt");
            outStr = processDecryptString(strInDoc, strPrivateKey, strPass, prop);
            logDebugInfo("Decrypt out String =" + outStr);
        } else if (strCryptoMethod != null && strCryptoMethod.equals(CryptoConstant.CRYPTO_ENCRYPT)) {
            logDebugInfo("inside else without Null for Encript");
            outStr = processEncryptString(strInDoc, strPubKey);
            logDebugInfo("Encrypt out String =" + outStr);
        }
        logDebugInfo("outDoc === " + outStr);
        return outStr;
    }

    private Document processDecrypt(Document inDocEncrypted) {

        logDebugInfo("processDecrypt Begin: " + " Input to processDecrypt Method is " + FileUtil.getXMLString(inDocEncrypted));
        InputStream secKeyIn = FileUtil.loadKey((String) props.get(CryptoConstant.SEC_KEY_PATH));
        String strSecKeyPasswd = (String) props.get(CryptoConstant.SECRET_KEY_PASSWORD);
        Node eleEncryptedOrder = inDocEncrypted.getFirstChild();
        String strEncyptedText = eleEncryptedOrder.getTextContent();

        logDebugInfo("strText : " + strEncyptedText + " strSecKeyPasswd :: " + strSecKeyPasswd);
        logDebugInfo("secKeyIn : " + secKeyIn + " eleEncryptedOrder :: " + eleEncryptedOrder);

        InputStream inStream = null;
        try {
            inStream = new ByteArrayInputStream(strEncyptedText.getBytes("UTF-8"));
            //	inStream = new ByteArrayInputStream(strEncyptedText.getBytes());
            logDebugInfo("inStream for strEncyptedText : " + inStream);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        String strOut = decrypt(inStream, secKeyIn, strSecKeyPasswd);
        logDebugInfo("strOut = " + strOut);
        Document outDoc = FileUtil.getXMlDocNew(strOut);
        return outDoc;
    }

    private String processDecryptString(String strInEncrypted, String strPrivateKey, String strPass, Properties props) {
        logDebugInfo("Inside processDecryptString");
        Document inDocEncrypted = FileUtil.getXMlDocNew(strInEncrypted);
        logDebugInfo("inDocEncrypted :" + FileUtil.getXMLString(inDocEncrypted));
        InputStream secKeyIn = FileUtil.loadKey((String) props.get(CryptoConstant.SEC_KEY_PATH));
        logDebugInfo("secKeyIn :" + secKeyIn);
        String strSecKeyPasswd = (String) props.get(CryptoConstant.SECRET_KEY_PASSWORD);
        logDebugInfo("strSecKeyPasswd :" + strSecKeyPasswd);
        Node eleEncryptedOrder = inDocEncrypted.getFirstChild();
        String strEncyptedText = eleEncryptedOrder.getTextContent();
        logDebugInfo("strEncyptedText :" + strEncyptedText);
        InputStream inStream = null;
        try {
            inStream = new ByteArrayInputStream(strEncyptedText.getBytes("UTF-8"));
            //inStream = new ByteArrayInputStream(strEncyptedText.getBytes());
            logDebugInfo("inStream in processDecryptString for  strEncyptedText :" + inStream);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        logDebugInfo(" Starting decryption");
        String strOut = decrypt(inStream, secKeyIn, strSecKeyPasswd);
        return strOut;
    }

    private String decrypt(InputStream fileIn, InputStream secKeyIn, String strSecKey) {

        String strOut = null;
        FileInputStream keyIn = (FileInputStream) secKeyIn;
        logDebugInfo(" Method decrypt ::  input info :: fileIn = " + fileIn + " \n Key in =  " + keyIn + " \n strSecKey = " + strSecKey);
        try {
            strOut = GPGUtil.decryptStream(fileIn, keyIn, strSecKey.toCharArray());
            logDebugInfo("inside decrypt : " + strOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return strOut;
    }

    private Document processEncrypt(Document inDoc) {
		
/*		private Document processEncrypt(YFSEnvironment env,
				Document inDoc) throws Exception {
			
		}
		
		if (YFCObject.isVoid(inDoc)) {
			throw new Exception("Input Document is null");
		}
		*/

        InputStream pubKeyIn = FileUtil.loadKey((String) props.get(CryptoConstant.PUB_KEY_PATH));
        PGPPublicKey pubKey = null;
        pubKey = readPublicKey(pubKeyIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        logDebugInfo("Input Doc : " + FileUtil.getXMLString(inDoc));
        String strOut = encrypt(out, inDoc, pubKey);
        Document outDoc = FileUtil.getXMlDocEncrypted(strOut);
        logDebugInfo("returning out Doc : " + outDoc);
        return outDoc;
    }

    private String processEncryptString(String strPlain, String strPubKeyPath) {
        Document inDoc = FileUtil.getXMlDocNew(strPlain);
        InputStream pubKeyIn = FileUtil.loadKey(strPubKeyPath);
        PGPPublicKey pubKey = null;
        pubKey = readPublicKey(pubKeyIn);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        logDebugInfo("Input Doc : " + FileUtil.getXMLString(inDoc));
        String strOut = encrypt(out, inDoc, pubKey);
        return "<Order><EncryptedOrder>\n" + strOut + "\n</EncryptedOrder></Order>";
    }

    private static PGPPublicKey readPublicKey(InputStream pubKeyIn) {
        PGPPublicKey pubKey = null;
        try {
            pubKey = GPGUtil.readPublicKey(pubKeyIn);
        } catch (IOException e) {

            e.printStackTrace();
        } catch (PGPException e) {

            e.printStackTrace();
        }
        return pubKey;
    }

    private static String encrypt(ByteArrayOutputStream out, Document inDoc, PGPPublicKey pubKey) {

        ByteArrayInputStream xmlByteArrayInputStream = (ByteArrayInputStream) FileUtil.getXMlStream(inDoc);
        String strOut = null;
        try {
            strOut = GPGUtil.encryptStream(out, xmlByteArrayInputStream, pubKey, true, true);
        } catch (NoSuchProviderException e) {

            e.printStackTrace();
        } catch (IOException e) {

            e.printStackTrace();
        }
        return strOut;
    }

    public static void main(String[] args) {
        GPGService gpg = new GPGService();
        Document inDocEncrypted = null;
        boolean encrypt = false;
        if (encrypt) {
            inDocEncrypted = FileUtil.loadInputXML("OrderCreate.xml");
        } else {
            inDocEncrypted = FileUtil.loadInputXML("WrappedCreateOrder.xml");
        }
        try {
            if (encrypt) {
                gpg.processCryptoString(FileUtil.getXMLString(inDocEncrypted), "ENCRYPT", "project.properties", "12345678");
            } else {
                gpg.processCryptoString(FileUtil.getXMLString(inDocEncrypted), "DECRYPT", "project.properties", "12345678");
            }
        } catch (Exception e) {

            e.printStackTrace();
        }
    }

    public void logDebugInfo(String info) {
        //remove System.out.println where required
        System.out.println(info);
      /* if (oBaseLog.isDebugEnabled()) {
            oBaseLog.debug(info);
      }
*/
    }

}
