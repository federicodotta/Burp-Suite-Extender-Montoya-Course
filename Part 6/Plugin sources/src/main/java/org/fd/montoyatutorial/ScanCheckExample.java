package org.fd.montoyatutorial;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

public class ScanCheckExample implements BurpExtension {

    MontoyaApi api;
    Logging logging;

    @Override
    public void initialize(MontoyaApi api) {

        // Save a reference to the MontoyaApi object
        this.api = api;

        // api.logging() returns an object that we can use to print messages to stdout and stderr
        this.logging = api.logging();

        // Set the name of the extension
        api.extension().setName("Montoya API tutorial - Scan Check Example");

        // Print a message to the stdout
        this.logging.logToOutput("*** Montoya API tutorial - Scan Check Example loaded ***");

        // Register our custom scan check
        this.api.scanner().registerScanCheck(new CustomScanCheck(api));

    }
}
