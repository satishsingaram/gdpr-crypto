package com.bingo.oms.crypto.crypto.util;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.util.Properties;

public class FileUtil {

    public static Properties loadProjectProperties(String strPropertiesFilePath) {
        Properties properties = new Properties();
        System.out.println("strPropertiesFilePath : " + strPropertiesFilePath);
        try {
            InputStream inputStream = new FileInputStream(strPropertiesFilePath);
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return properties;
    }

    public static InputStream loadKey(String strKeyPath) {
        InputStream inputStream = null;
        System.out.println("strKeyPath : " + strKeyPath);
        try {
            inputStream = new FileInputStream(strKeyPath);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return inputStream;
    }

    public static Document loadInputXML(String strXMLFilePath) {
        System.out.println("strXMLFilePath : " + strXMLFilePath);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document document = null;
        try {
            DocumentBuilder builder;
            builder = factory.newDocumentBuilder();
            document = builder.parse(new File(strXMLFilePath));
            document.getDocumentElement().normalize();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParserConfigurationException e) {

        } catch (SAXException e) {

        }
        return document;
    }

    public static String getXMLString(Document xmlDocument) {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer;
        String xmlString = null;
        try {
            transformer = tf.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(xmlDocument), new StreamResult(writer));
            xmlString = writer.getBuffer().toString();
            System.out.println(xmlString);                      //Print to console or logs
        } catch (TransformerException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return xmlString;
    }

    public static InputStream getXMlStream(Document inDoc) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Source xmlSource = new DOMSource(inDoc);
        Result outputTarget = new StreamResult(outputStream);
        try {
            TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        } catch (TransformerFactoryConfigurationError e) {
            e.printStackTrace();
        }
        InputStream is = new ByteArrayInputStream(outputStream.toByteArray());
        return is;
    }

    public static Document getXMlDoc(InputStream in) {
        DocumentBuilder db = null;
        try {
            db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        } catch (ParserConfigurationException e1) {
            e1.printStackTrace();
        }
        Document document = db.newDocument();
        Source xmlSource = new StreamSource(in);
        DOMResult outputTarget = new DOMResult(document);
        try {
            TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget);
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        } catch (TransformerFactoryConfigurationError e) {
            e.printStackTrace();
        }
        Document outDoc = ((Document) outputTarget.getNode()).getOwnerDocument();
        return outDoc;
    }

    public static Document getXMlDocNew(String strInput) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
            Document outDoc = builder.parse(new InputSource(new StringReader(strInput)));
            return outDoc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Document getXMlDocEncrypted(String strInput) {
        String strXMLPrefix = "<Order><EncryptedOrder>";
        String strXMLPostfix = "</EncryptedOrder></Order>";
        strInput = strXMLPrefix + strInput + strXMLPostfix;
        System.out.println("strInput#### :" + strInput);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
            Document outDoc = builder.parse(new InputSource(new StringReader(strInput)));
            return outDoc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void writeToFile(String strPath, ByteArrayOutputStream bout) {
        OutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(strPath);
        } catch (FileNotFoundException e) {

            e.printStackTrace();
        }
        try {
            bout.writeTo(outputStream);
        } catch (IOException e) {

            e.printStackTrace();
        }
    }

}
