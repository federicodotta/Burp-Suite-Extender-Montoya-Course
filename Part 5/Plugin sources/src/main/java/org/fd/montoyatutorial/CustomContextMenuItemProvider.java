package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.utilities.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static burp.api.montoya.core.ByteArray.byteArray;

public class CustomContextMenuItemProvider implements ContextMenuItemsProvider {

    static String keyHex = "eeb27c55483270a92682dab01b85fdea";
    static String ivHex = "ecbc1312cfdc2a0e1027b1eaf577dce8";

    MontoyaApi api;
    Logging logging;
    Base64Utils base64Utils;

    public CustomContextMenuItemProvider(MontoyaApi api) {

        // Save a reference to the MontoyaApi object
        this.api = api;
        // Save a reference to the logging object of the MontoyaApi
        this.logging = api.logging();
        // Save a reference to the Base64 utilities offere by the MontoyaApi
        this.base64Utils = api.utilities().base64Utils();

    }

    public static byte[] encryptDecrypt(int encryptionOrDecryption, byte[] data, Logging logging) {

        try {

            // Create a specific object containing the IV for encryption
            byte[] iv = HexFormat.of().parseHex(ivHex);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Create a specific object containing the key for encryption
            byte[] key = HexFormat.of().parseHex(keyHex);
            SecretKey SecKey = new SecretKeySpec(key, 0, key.length, "AES");

            // Initialize our AER cipher
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(encryptionOrDecryption, SecKey, ivParameterSpec);

            // Encrypt or decrypt the input data
            byte[] processedMessage = aesCipher.doFinal(data);

            return processedMessage;

        } catch (Exception e) {

            logging.logToError(e.toString());
            return null;

        }

    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {

        // Initialize an empty list that will contains our context menu entries
        List<Component> menuItems = new ArrayList<Component>();

        // Create the menu only if the menu has been created on a request/response object
        event.messageEditorRequestResponse().ifPresent(messageEditorReqRes -> {

            // Create the menu only if the request/response has a selected portion
            messageEditorReqRes.selectionOffsets().ifPresent(selectionOffset -> {

                // Get the HTTP message
                HttpRequestResponse reqRes = messageEditorReqRes.requestResponse();

                // Necessary to understand if the context menu has been created on a request or on a response
                MessageEditorHttpRequestResponse.SelectionContext selectionContext = messageEditorReqRes.selectionContext();

                // Create the "Decrypt" entry of the context menu
                JMenuItem decryptItem = new JMenuItem("Decrypt");
                decryptItem.addActionListener(al -> {

                    ByteArray requestResponseBytes;
                    // Request
                    if(selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                        requestResponseBytes = reqRes.request().toByteArray();
                    // Response
                    } else {
                        requestResponseBytes = reqRes.response().toByteArray();
                    }

                    // Get the selected portion of the request/response in ByteArray
                    ByteArray selectedBytes = requestResponseBytes.subArray(selectionOffset.startIndexInclusive(),
                            selectionOffset.endIndexExclusive());

                    // Base64 decode the selected portion
                    ByteArray decodedSelectedBytes = this.api.utilities().base64Utils().decode(selectedBytes);

                    // Decrypt the selected portion
                    byte[] decryptedMessage = encryptDecrypt(Cipher.DECRYPT_MODE,decodedSelectedBytes.getBytes(),logging);
                    String decryptedMessageString = new String(decryptedMessage);

                    // Create a new HTTP message that contains the decrypted value instead of the
                    // selected portion of the message
                    ByteArray editedRequestResponseBytes = requestResponseBytes.subArray(0,selectionOffset.startIndexInclusive());
                    editedRequestResponseBytes = editedRequestResponseBytes.withAppended(byteArray(decryptedMessage));
                    if(selectionOffset.endIndexExclusive()<requestResponseBytes.length())
                        editedRequestResponseBytes = editedRequestResponseBytes.withAppended(requestResponseBytes.subArray(selectionOffset.endIndexExclusive(),requestResponseBytes.length()));
                    String editedRequestResponseString = editedRequestResponseBytes.toString();

                    // Try to replace the original HTTP message with the new one. This operation may fail if the
                    // request/response is not editable (es. in the History of the Proxy)
                    try {

                        // Request
                        if(selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                            messageEditorReqRes.setRequest(HttpRequest.httpRequest(editedRequestResponseBytes));
                        // Response
                        } else {
                            messageEditorReqRes.setResponse(HttpResponse.httpResponse(editedRequestResponseBytes));
                        }

                    } catch (UnsupportedOperationException ex) {

                        // If the request/response is not editable, an UnsupportedOperationException arises and
                        // we print our edited message in a popup.
                        SwingUtilities.invokeLater(new Runnable() {

                            @Override
                            public void run() {

                                JTextArea ta = new JTextArea(20, 60);
                                ta.setLineWrap(true);
                                ta.setText(decryptedMessageString);
                                JOptionPane.showMessageDialog(null, new JScrollPane(ta), "Edited message", JOptionPane.INFORMATION_MESSAGE);

                            }

                        });

                    }

                });

                JMenuItem encryptItem = new JMenuItem("Encrypt");
                encryptItem.addActionListener(al -> {

                    ByteArray requestResponseBytes;
                    // Request
                    if(selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                        requestResponseBytes = reqRes.request().toByteArray();
                        // Response
                    } else {
                        requestResponseBytes = reqRes.response().toByteArray();
                    }

                    // Get the selected portion of the request/response in ByteArray
                    ByteArray selectedBytes = requestResponseBytes.subArray(selectionOffset.startIndexInclusive(),
                            selectionOffset.endIndexExclusive());

                    // Encrypt the selected portion
                    byte[] encryptedMessage = encryptDecrypt(Cipher.ENCRYPT_MODE,selectedBytes.getBytes(),logging);

                    // Encode the encrypted value in Base64
                    ByteArray encodedMessage = this.api.utilities().base64Utils().encode(ByteArray.byteArray(encryptedMessage));
                    String encodedMessageString =  encodedMessage.toString();

                    // Create a new HTTP message that contains the encrypted value instead of the
                    // selected portion of the message
                    ByteArray editedRequestResponseBytes = requestResponseBytes.subArray(0,selectionOffset.startIndexInclusive());
                    editedRequestResponseBytes = editedRequestResponseBytes.withAppended(encodedMessage);
                    if(selectionOffset.endIndexExclusive()<requestResponseBytes.length())
                        editedRequestResponseBytes = editedRequestResponseBytes.withAppended(requestResponseBytes.subArray(selectionOffset.endIndexExclusive(),requestResponseBytes.length()));

                    // Try to replace the original HTTP message with the new one. This operation may fail if the
                    // request/response is not editable (es. in the History of the Proxy)
                    try {

                        // Request
                        if (selectionContext == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                            messageEditorReqRes.setRequest(HttpRequest.httpRequest(editedRequestResponseBytes));
                            // Response
                        } else {
                            messageEditorReqRes.setResponse(HttpResponse.httpResponse(editedRequestResponseBytes));
                        }

                    } catch (UnsupportedOperationException ex) {

                        // If the request/response is not editable, an UnsupportedOperationException arises and
                        // we print our edited message in a popup.
                        SwingUtilities.invokeLater(new Runnable()  {

                            @Override
                            public void run()  {

                                JTextArea ta = new JTextArea(20, 60);
                                ta.setLineWrap(true);
                                ta.setText(encodedMessageString);
                                JOptionPane.showMessageDialog(null, new JScrollPane(ta), "Edited message", JOptionPane.INFORMATION_MESSAGE);

                            }

                        });

                    }

                });

                // Add the new items to the list we will return
                menuItems.add(decryptItem);
                menuItems.add(encryptItem);

            });


        });

        return menuItems;

    }

}
