package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;

import java.math.BigInteger;
import java.util.List;

public class CustomHttpHandler implements HttpHandler {

    MontoyaApi api;
    Logging logging;

    public CustomHttpHandler(MontoyaApi api) {
        // Save a reference to the MontoyaApi object
        this.api = api;
        // api.logging() returns an object that we can use to print messages to stdout and stderr
        this.logging = api.logging();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

        if(requestToBeSent.toolSource().isFromTool(ToolType.REPEATER, ToolType.SCANNER, ToolType.INTRUDER)) {

            // Get a list of HTTP headers of the request
            List<HttpHeader> headers = requestToBeSent.headers();

            // 1 - Check if the list contains an header named "Hash" (using Java streams, introduced in Java 8)
            if (headers.stream().map(HttpHeader::name).anyMatch(h -> h.trim().equals("Hash"))) {

                // 2 - Extract the body of the request, using "body" function of the HttpRequestToBeSent object
                // https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/handler/HttpRequestToBeSent.html
                ByteArray body = requestToBeSent.body();

                // Get a reference to the CryptoUtils offered by Burp Suite
                // https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/utilities/CryptoUtils.html
                CryptoUtils cryptoUtils = api.utilities().cryptoUtils();

                // 3 - Calculate SHA256 hash
                ByteArray sha256hash = cryptoUtils.generateDigest(body, DigestAlgorithm.SHA_256);

                // Convert SHA256 bytes to a HEX string, using a Java way
                String digest = String.format("%064x", new BigInteger(1, sha256hash.getBytes()));

                // 4 - Set the hash in the "Hash" HTTP header
                HttpRequest modifiedRequest = requestToBeSent.withUpdatedHeader("Hash", digest);

                // 5 - Return the modified request
                return RequestToBeSentAction.continueWith(modifiedRequest);

            }

        }

        // If the request does not contain a header named "Hash" return the original request
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // We are not interested in responses, so we simply return original ones
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
