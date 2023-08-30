package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.utilities.Base64Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.util.HexFormat;

import static burp.api.montoya.core.ByteArray.byteArray;

public class CustomHttpRequestEditorTab implements ExtensionProvidedHttpRequestEditor {

    static String keyHex = "eeb27c55483270a92682dab01b85fdea";
    static String ivHex = "ecbc1312cfdc2a0e1027b1eaf577dce8";

    MontoyaApi api;
    Logging logging;
    EditorCreationContext creationContext;
    RawEditor requestEditorTab;
    Base64Utils base64Utils;
    HttpRequestResponse currentRequestResponse;

    public CustomHttpRequestEditorTab(MontoyaApi api, EditorCreationContext creationContext) {

        // Save argument of constructor in object
        this.api = api;
        this.creationContext = creationContext;

        // Save references to object that we will use
        this.logging = api.logging();
        this.base64Utils = api.utilities().base64Utils();

        // Initialize our editor tab (Type RawEditor) in read only mode if the request is read only,
        // read/write otherwise
        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            requestEditorTab = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        } else {
            requestEditorTab = api.userInterface().createRawEditor();
        }
    }

    @Override
    public HttpRequest getRequest() {

        if(isModified()) {

            ByteArray newBody = requestEditorTab.getContents();

            try {

                // Create a specific object containing the IV for encryption
                byte[] iv = HexFormat.of().parseHex(this.ivHex);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

                // Create a specific object containing the key for encryption
                byte[] key = HexFormat.of().parseHex(this.keyHex);
                SecretKey SecKey = new SecretKeySpec(key, 0, key.length, "AES");

                // Initialize our AER cipher in DECRYPT mode
                Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aesCipher.init(Cipher.ENCRYPT_MODE, SecKey, ivParameterSpec);

                // Decrypt the body
                byte[] encryptedBody = aesCipher.doFinal(newBody.getBytes());

                // Encode the encrypted value in Base64
                ByteArray encodedBody = this.base64Utils.encode(ByteArray.byteArray(encryptedBody));

                // Extract the request from the HttpRequestResponse we save in the setRequestResponse
                HttpRequest oldRequest = this.currentRequestResponse.request();

                // Replace its body with the new encrypted and encoded body and return the modified request
                HttpRequest newRequest = oldRequest.withBody(encodedBody);
                return newRequest;

            } catch (Exception e) {

                // Log exceptions (if any)
                this.logging.logToError(e);

                // Return original request
                return this.currentRequestResponse.request();

            }

        } else {

            // Return original request if decrypted body was not modified
            return this.currentRequestResponse.request();

        }

    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {

        // Extract the request and its body
        HttpRequest request = requestResponse.request();
        ByteArray body = request.body();

        // Base64 decode
        ByteArray decodedBody = this.base64Utils.decode(body);

        // Save current requestResponse (we will need this object to build a new request
        // if the decrypted content will be modified)
        this.currentRequestResponse = requestResponse;

        try {

            // Create a specific object containing the IV for encryption
            byte[] iv = HexFormat.of().parseHex(this.ivHex);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            // Create a specific object containing the key for encryption
            byte[] key = HexFormat.of().parseHex(this.keyHex);
            SecretKey SecKey = new SecretKeySpec(key, 0, key.length, "AES");

            // Initialize our AER cipher in DECRYPT mode
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, SecKey, ivParameterSpec);

            // Decrypt the body
            byte[] decryptedBody = aesCipher.doFinal(decodedBody.getBytes());

            // Set the decrypted value in our custom tab
            this.requestEditorTab.setContents(byteArray(decryptedBody));

        } catch (Exception e) {

            // Log exceptions (if any)
            this.logging.logToError(e);

        }

    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {

        // Our tab is always enabled. In this method you can choose if you want to enable
        // the custom tab, basing on the value of the request, the context, etc.
        return true;

    }

    @Override
    public String caption() {

        // The name of the tab
        return "Decrypted";

    }

    @Override
    public Component uiComponent() {

        // Get the UI component of the tab (returned by the RawEditor object we use)
        return requestEditorTab.uiComponent();

    }

    @Override
    public Selection selectedData() {

        // This method should return selected data in tab, if any. We can use method offered
        // by the RawEditor object to check if any data is selected and, if so, return this data
        if(requestEditorTab.selection().isPresent()) {
            return requestEditorTab.selection().get();
        } else {
            return null;
        }

    }

    @Override
    public boolean isModified() {

        // This method should return true if the data inside our custom tab has been modified by
        // the user. The RawEditor tab has a method with the same name that return this information
        return requestEditorTab.isModified();

    }
}
