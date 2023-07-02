package org.fd.montoyatutorial;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class HttpHandlerExample implements BurpExtension {

    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {

        // Save a reference to the MontoyaApi object
        this.api = api;

        // api.logging() returns an object that we can use to print messages to stdout and stderr
        this.logging = api.logging();

        // Set the name of the extension
        api.extension().setName("Montoya API tutorial - HttpHandlerExample");

        // Print a message to the stdout
        this.logging.logToOutput("*** Montoya API tutorial - HttpHandlerExample loaded ***");

        // Register our HttpHandler
        api.http().registerHttpHandler(new CustomHttpHandler(api));

    }
}
