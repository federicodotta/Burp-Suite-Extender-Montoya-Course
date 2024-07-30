package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.utilities.Utilities;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class CustomScanCheck implements ScanCheck {

    // Magic bytes of a serialized Java object (not encoded and Base64 encoded)
    private byte[] serializationMagicBytes = {(byte)0xac, (byte)0xed, (byte)0x00, (byte)0x05};
    private byte[] base64MagicBytes = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};

    MontoyaApi api;
    Utilities utilities;

    public CustomScanCheck(MontoyaApi api) {

        // Save references to usefull objects
        this.api = api;
        this.utilities = this.api.utilities();

    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {

        // Inizialize an empty list of audit issues that we will eventually populate and return at the end of the function
        List<AuditIssue> activeAuditIssues = new ArrayList<AuditIssue>();

        // For each CommonsCollections 3 payload we defined, we try to exploit the issue
        for(int i = 0; i< StaticItems.apacheCommonsCollections3Payloads.length; i++) {

            // We create an HTTP request containing our payload in the current insertion point
            HttpRequest commonsCollectionsCheckRequest = auditInsertionPoint.buildHttpRequestWithPayload(
                    ByteArray.byteArray(StaticItems.apacheCommonsCollections3Payloads[i]))
                    .withService(baseRequestResponse.httpService());

            // We record the current time, execute the request and record the time again
            long startTime = System.nanoTime();
            HttpRequestResponse commonsCollectionsCheckRequestResponse = api.http().sendRequest(commonsCollectionsCheckRequest);
            long endTime = System.nanoTime();

            // We calculate the internal between when we sent the request and when we received the response (converted in seconds)
            long duration = TimeUnit.SECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS);

            // If the internval is greater than 9 seconds we may have a vulnerable endpoint (our payloads sleep for 10 seconds)
            if (((int) duration) >= 9) {

                // In this case, we create an issue object and adds it to the list of issues to be returned
                AuditIssue auditIssue = AuditIssue.auditIssue(StaticItems.apacheCommonsCollections3IssueName,
                        StaticItems.apacheCommonsCollections3IssueDetail,
                        null, // remediation
                        baseRequestResponse.request().url(),
                        StaticItems.apacheCommonsCollections3IssueSeverity,
                        StaticItems.apacheCommonsCollections3IssueConfidence,
                        null, // background
                        null, // remediationBackground
                        StaticItems.apacheCommonsCollections3IssueTypicalSeverity,
                        commonsCollectionsCheckRequestResponse); //Request/response can be highlighted

                activeAuditIssues.add(auditIssue);

            }

        }

        // Return the list of issues
        return AuditResult.auditResult(activeAuditIssues);

    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {

        // Inizialize an empty list of audit issues that we will eventually populate and return at the end of the function
        List<AuditIssue> passiveAuditIssues = new ArrayList<AuditIssue>();

        //Extract request bytes
        ByteArray request = baseRequestResponse.request().toByteArray();

        // Check for the magic bytes of Java serialized object (not encoded and Base64 encoded)
        int indexOfSerializationMagicBytes = request.indexOf(ByteArray.byteArray(serializationMagicBytes));
        int indexOfBase64MagicBytes = request.indexOf(ByteArray.byteArray(base64MagicBytes));

        // Improvement -> Search all matches with a while instead of an if

        // If we found the magic bytes we report the passive issue
        if(indexOfSerializationMagicBytes != -1 || indexOfBase64MagicBytes != -1) {

            // Calculate the indexes to highligh the start of the serialized object in the request
            int startIndex;
            if(indexOfSerializationMagicBytes != -1)
                startIndex = indexOfSerializationMagicBytes;
            else
                startIndex = indexOfBase64MagicBytes;
            int endIndex = startIndex+4;

            // Create the markers to highlight the request in the reported issue
            List<Marker> highlights = new ArrayList<Marker>();
            Marker marker = Marker.marker(startIndex, endIndex);
            highlights.add(marker);

            // Report the passive issue
            AuditIssue auditIssue = AuditIssue.auditIssue(StaticItems.passiveSerializationIssueName,
                    StaticItems.passiveSerializationIssueDetail,
                    null, // remediation
                    baseRequestResponse.request().url(),
                    StaticItems.passiveSerializationIssueSeverity,
                    StaticItems.passiveSerializationIssueConfidence,
                    null, // background
                    null, // remediationBackground
                    StaticItems.passiveSerializationIssueTypicalSeverity,
                    baseRequestResponse.withRequestMarkers(highlights));

            passiveAuditIssues.add(auditIssue);


        }

        // Return the list of issues
        return AuditResult.auditResult(passiveAuditIssues);

    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {

        // Improvement: extract HttpRequestResponses and keep existing only if the
        // attack vector has been inserted in the same parameter, but adds complexity

        // If the new issue has the same name and base URL of the one of the older ones, keep only the new one
        if(newIssue.name().equals(existingIssue.name()) && newIssue.baseUrl().equals(existingIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        } else {
            // Otherwise keep both the issues
            return ConsolidationAction.KEEP_BOTH;
        }

    }

}
