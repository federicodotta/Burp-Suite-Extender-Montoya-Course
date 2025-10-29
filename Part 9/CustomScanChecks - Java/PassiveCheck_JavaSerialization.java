/**
 * Passively detect serialized object (raw or base64 encoded in HTTP requests)
 * 
 * @author apps3c
**/

// Serialization magic bytes
byte[] serializationMagicBytes = {(byte)0xac, (byte)0xed, (byte)0x00, (byte)0x05};
byte[] base64MagicBytes = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};

// Extract request bytes
ByteArray request = requestResponse.request().toByteArray();

// Check for the magic bytes of Java serialized object (not encoded and Base64 encoded)
int indexOfSerializationMagicBytes = request.indexOf(ByteArray.byteArray(serializationMagicBytes));
int indexOfBase64MagicBytes = request.indexOf(ByteArray.byteArray(base64MagicBytes));

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
    
    String passiveSerializationIssueName = "Serialized Java objects detected";
    String passiveSerializationIssueDetail = "Serialized Java objects have been detected in the body"+
        " or in the parameters of the request. If the server application does "+
        " not check on the type of the received objects before"+
        " the deserialization phase, it may be vulnerable to the Java Deserialization"+
        " Vulnerability.";

    // Report the passive issue
    return AuditResult.auditResult(AuditIssue.auditIssue(
        passiveSerializationIssueName,
        passiveSerializationIssueDetail,
            null, // remediation
            requestResponse.request().url(),
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.FIRM,
            null, // background
            null, // remediationBackground
            AuditIssueSeverity.INFORMATION,
            requestResponse.withRequestMarkers(highlights)));

} else {

    return AuditResult.auditResult();
    
}


