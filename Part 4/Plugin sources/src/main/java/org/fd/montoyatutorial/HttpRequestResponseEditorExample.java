package org.fd.montoyatutorial;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class HttpRequestResponseEditorExample implements BurpExtension {

    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {

        // Save a reference to the MontoyaApi object
        this.api = api;

        // api.logging() returns an object that we can use to print messages to stdout and stderr
        this.logging = api.logging();

        // Set the name of the extension
        api.extension().setName("Montoya API tutorial - HttpRequestResponseEditorExample");

        // Print a message to the stdout
        this.logging.logToOutput("*** Montoya API tutorial - HttpRequestResponseEditorExample loaded ***");

        // Register our CustomHttpRequestResponseEditor for both requests and responses
        // Note: we used a single class for both requests and responses (that implements both
        // HttpRequestEditorProvider and HttpResponseEditorProvider interfaces but we can also use
        // two different classes, one for requests and one for responses).
        CustomHttpRequestResponseEditor customHttpRequestResponseEditor = new CustomHttpRequestResponseEditor(api);
        api.userInterface().registerHttpRequestEditorProvider(customHttpRequestResponseEditor);
        api.userInterface().registerHttpResponseEditorProvider(customHttpRequestResponseEditor);

    }
}