package com.bingo.oms.crypto.crypto.util;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class GPGUtil {

    /**
     * Logger instance.
     */
    //private static Logger log = new Logger(GPGUtil.class);

    /*
     * Initializing logging and api object
     */

    //private static YFCLogCategory oBaseLog = YFCLogCategory.instance(GPGUtil.class.getName());
    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in);
        Iterator rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
            Iterator kIt = kRing.getPublicKeys();

            while (kIt.hasNext()) {
                PGPPublicKey k = (PGPPublicKey) kIt.next();

                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    public static String encryptStream(OutputStream out, ByteArrayInputStream in, PGPPublicKey encKey, boolean armor, boolean withIntegrityCheck) throws IOException, NoSuchProviderException {
        ByteArrayOutputStream bos = (ByteArrayOutputStream) out;
        String strOut = null;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {

            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(), "BC");
            cPk.addMethod(encKey);
            OutputStream cOut = cPk.open(out, new byte[1 << 16]);
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            writeStream(comData.open(cOut), PGPLiteralData.BINARY, in, new byte[1 << 16]);
            comData.close();
            cOut.close();
            out.close();
            strOut = new String(bos.toByteArray(), "UTF-8");

        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
        return strOut;
    }

    public static void writeStream(OutputStream out, char fileType, ByteArrayInputStream in, byte[] buffer) throws IOException {

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, "", in.available(), new Date());
        byte[] buf = new byte[buffer.length];
        int len;
        while ((len = in.read(buf)) > 0) {
            pOut.write(buf, 0, len);
        }
        lData.close();
        in.close();
    }

    public static void decryptFile(InputStream in, InputStream keyIn, char[] passwd, String defaultFileName) throws Exception {
        in = PGPUtil.getDecoderStream(in);

        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            PGPEncryptedDataList enc = null;
            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }
            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            InputStream clear = pbe.getDataStream(sKey, "BC");
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                String outFileName = ld.getFileName();
                if (ld.getFileName().length() == 0) {
                    outFileName = defaultFileName;
                }
                FileOutputStream fOut = new FileOutputStream(outFileName);
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) {
                    fOut.write(ch);
                }

            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    public static String decryptStream(InputStream in, InputStream keyIn, char[] passwd) throws Exception {
        System.out.println( javax.crypto.Cipher.getMaxAllowedKeyLength("AES"));
        logDebugInfo("decryptStream Begin: in stream = " + in + "\n Key Instream = " + keyIn + " \n passwd = " + passwd);
        in = PGPUtil.getDecoderStream(in);
        String strOut = null;
        logDebugInfo("inside decryptStream : " + in);
        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(in);
            PGPEncryptedDataList enc = null;
            Object o = pgpF.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            logDebugInfo("inside try block, value of pgpF.nextObject() :: " + o);
            if (o instanceof PGPEncryptedDataList) {
                logDebugInfo("inside instance of PGPEncryptedDataList");
                enc = (PGPEncryptedDataList) o;
                logDebugInfo("PGPEncryptedDataList - value of enc = " + enc);
            } else {
                logDebugInfo("inside not PGPEncryptedDataList. getting next object");
                enc = (PGPEncryptedDataList) pgpF.nextObject();
                logDebugInfo("inside not PGPEncryptedDataList - value of enc = " + enc);
            }

            //
            // find the secret key
            //
            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));

            while (sKey == null && it.hasNext()) {
                logDebugInfo("sKey is null");
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
                logDebugInfo("sKey is null, pbe = " + pbe + " sKey = " + sKey);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(sKey, "BC");
            PGPObjectFactory plainFact = new PGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            logDebugInfo("getting message  :: " + message);

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                ByteArrayOutputStream fOut = new ByteArrayOutputStream();
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) {
                    fOut.write(ch);
                }
                fOut.close();
                strOut = fOut.toString();
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }
            logDebugInfo("done decrypting message ");
            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                } else {
                    System.err.println("message integrity check passed");
                }
            } else {
                System.err.println("no message integrity check");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
        return strOut;
    }

    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }
        return pgpSecKey.extractPrivateKey(pass, "BC");
    }

    public static void logDebugInfo(String info) {
        //remove System.out.println when necessary
        System.out.println(info);
        /*if (oBaseLog.isDebugEnabled()) {
            oBaseLog.debug(info);
        }*/
    }
}
