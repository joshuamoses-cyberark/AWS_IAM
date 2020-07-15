package ConjurApi.AwsIamAuthn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * The ConjurAwsIamAuthn utility will create a signed request to the AWS STS
 * which is used by the conjur server to authenticate as an IAM role
 * 
 * More information regarding how this is done can he found here: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 * 
 */
public class ConjurAwsIamAuthn {
	public static String HOST = "sts.amazonaws.com";
	public static String REGION = "us-east-1";
	public static String SERVICE = "sts";	
	public static String SIGNED_HEADERS = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
	
	public static byte[] hmacSHA256(String data, byte[] key) throws Exception {
	    String algorithm="HmacSHA256";
	    Mac mac = Mac.getInstance(algorithm);
	    mac.init(new SecretKeySpec(key, algorithm));
	    return mac.doFinal(data.getBytes("UTF-8"));
	}

	public static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
	    byte[] kSecret = ("AWS4" + key).getBytes("UTF-8");
	    byte[] kDate = hmacSHA256(dateStamp, kSecret);
	    byte[] kRegion = hmacSHA256(regionName, kDate);
	    byte[] kService = hmacSHA256(serviceName, kRegion);
	    byte[] kSigning = hmacSHA256("aws4_request", kService);
	    return kSigning;
	}
	
	public static String getAmzDate(Date now) {
		SimpleDateFormat timeFormat = new SimpleDateFormat("HHmmss");
		timeFormat.setTimeZone(TimeZone.getTimeZone("utc"));

		String first = getDate(now);
		String second = timeFormat.format(now);
		
		return first + "T" + second + "Z";
	}
	
	public static String getDate(Date now) {
		SimpleDateFormat yearMonthDayFormat = new SimpleDateFormat("yyyyMMdd");
		yearMonthDayFormat.setTimeZone(TimeZone.getTimeZone("utc"));
		return yearMonthDayFormat.format(now);
	}
	
	public static String createCanonicalRequest(String amzdate, String token, String signedHeaders, String payloadHash) {
		String canonicalUri = "/";
		String canonicalQueryString = "Action=GetCallerIdentity&Version=2011-06-15";
	    String canonicalHeaders = "host:" + HOST + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzdate + "\n" + "x-amz-security-token:" + token + "\n";
	    String canonicalRequest = "GET" + "\n" + canonicalUri + "\n" + canonicalQueryString + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;
	    return canonicalRequest;
	}
	
	public static String getCredentialScope(String datestamp) {
		return datestamp + '/' + REGION + '/' + SERVICE + '/' + "aws4_request";
	}
	
	public static String createStringToSign(String datestamp, String amzdate, String cannonicalRequest) {
		String algorithm = "AWS4-HMAC-SHA256";
	    String credentialScope = getCredentialScope(datestamp);
	    String stringToSign = algorithm + "\n" + amzdate + "\n" + credentialScope + "\n" + sha256(cannonicalRequest);
		return stringToSign;
	}
	
	public static String sha256(String input) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
			return toHexString(hash);
		} catch (NoSuchAlgorithmException e) {
			// this should never happen
			e.printStackTrace();
		}
		return null;
	}
	
	public static String toHexString(byte[] bytes) {
	    StringBuilder hexString = new StringBuilder();

	    for (int i = 0; i < bytes.length; i++) {
	        String hex = Integer.toHexString(0xFF & bytes[i]);
	        if (hex.length() == 1) {
	            hexString.append('0');
	        }
	        hexString.append(hex);
	    }

	    return hexString.toString();
	}
	
	public static String signString(String stringToSign, byte[] signingKey) throws Exception {
		return toHexString(hmacSHA256(stringToSign, signingKey));
	}
	
	public static String getAuthorizationHeader(String accessKey, String credentialScope, String signedHeaders, String signature) {
		String algorithm = "AWS4-HMAC-SHA256";
		return algorithm + " " + "Credential=" + accessKey + '/' + credentialScope + ", " + "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;
	}

	public static String headerAsJsonString(String amzdate, String token, String payloadHash, String authorizationHeader) {
	    String headerTemplate = "{\"host\": \"%s\", \"x-amz-date\": \"%s\", \"x-amz-security-token\": \"%s\", \"x-amz-content-sha256\": \"%s\", \"authorization\": \"%s\"}";
		return String.format(headerTemplate, HOST, amzdate, token, payloadHash, authorizationHeader);
	    
	}
	
	public static String getApiKey(String iamRoleName, String accessKey, String secretKey, String sessionToken) {		
		Date now = new Date();
		String amzdate = getAmzDate(now);
		String datestamp = getDate(now);
		
		String signedHeaders = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
		// payload is empty hence the hardcoded hash
		String payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
		
		String canonicalRequest = createCanonicalRequest(amzdate, sessionToken, signedHeaders, payloadHash);
		String stringToSign = createStringToSign(datestamp, amzdate, canonicalRequest);
		String signature = "";
		try {
			byte[] signingKey = getSignatureKey(secretKey, datestamp, REGION, SERVICE);
			signature = signString(stringToSign, signingKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		String authorizationHeader = getAuthorizationHeader(accessKey, getCredentialScope(datestamp), SIGNED_HEADERS, signature);
		return headerAsJsonString(amzdate, sessionToken, payloadHash, authorizationHeader);
	}

}
