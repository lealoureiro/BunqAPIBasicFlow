package com.leandroloureiro.bunqapi;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * @author Leandro Loureiro
 */
public class BunqAPI {


    private static final Logger LOGGER = LogManager.getLogger(BunqAPI.class.getName());

    private static final String CACHE_CONTROL_HEADER = "Cache-Control";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String BUNQ_CLIENT_AUTHENTICATION_HEADER = "X-Bunq-Client-Authentication";
    private static final String BUNQ_CLIENT_SIGNATURE_HEADER = "X-Bunq-Client-Signature";
    private static final String BUNQ_CLIENT_REQUEST_ID_HEADER = "X-Bunq-Client-Request-Id";
    private static final String BUNQ_GEOLOCATION_HEADER = "X-Bunq-Geolocation";
    private static final String BUNQ_LANGUAGE_HEADER = "X-Bunq-Language";
    private static final String BUNQ_REGION_HEADER = "X-Bunq-Region";
    private static final String BUNQ_SERVER_SIGNATURE = "X-Bunq-Server-Signature";

    private static final String NO_CACHE = "no-cache";
    private static final String NO_GEOLOCATION = "0 0 0 0 000";
    private static final String EN_US = "en_US";
    private static final String LINE_FEED = "\n";

    private static final String BUNQ_API_URI = "https://sandbox.public.api.bunq.com/v1";
    private static final String USER_AGENT = "LeandroBunqGateway";
    private static final String BUNQ_HEADER_PREFIX = "X-Bunq";

    private final String apiKey;
    private final byte[] privateKey;

    private String installationToken;
    private String sessionToken;
    private byte[] serverPublicKey;
    private int loggedUserId;

    public BunqAPI(final String apiKey, final byte[] privateKey) {
        this.apiKey = apiKey;
        this.privateKey = privateKey;
    }

    public void installation(final String publicKey) {

        LOGGER.debug("Performing Installation");

        try {

            final String body = String.format("{\"client_public_key\": \"%s\"}", publicKey);

            LOGGER.debug("Sending body: {}", body);

            final HttpResponse<JsonNode> jsonResponse = Unirest.post(String.format("%s/installation", BUNQ_API_URI))
                    .header(CACHE_CONTROL_HEADER, NO_CACHE)
                    .header(BUNQ_CLIENT_REQUEST_ID_HEADER, UUID.randomUUID().toString())
                    .header(BUNQ_GEOLOCATION_HEADER, NO_GEOLOCATION)
                    .header(BUNQ_LANGUAGE_HEADER, EN_US)
                    .header(BUNQ_REGION_HEADER, EN_US)
                    .body(body)
                    .asJson();

            LOGGER.debug("Installation response code: {}", jsonResponse.getStatus());
            LOGGER.debug("Installation response body: {}", jsonResponse.getBody().toString());

            final JSONArray response = (JSONArray) jsonResponse.getBody().getObject().get("Response");
            final JSONObject tokenDetails = (JSONObject) ((JSONObject) response.get(1)).get("Token");
            final JSONObject publicKeyDetails = (JSONObject) ((JSONObject) response.get(2)).get("ServerPublicKey");

            installationToken = tokenDetails.getString("token");
            final String formattedServerPublicKey = publicKeyDetails.getString("server_public_key");
            final String filteredServerPublicKey = formattedServerPublicKey.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").trim();
            serverPublicKey = DatatypeConverter.parseBase64Binary(filteredServerPublicKey);

        } catch (final UnirestException e) {
            LOGGER.error("Problem when performing installation", e);
        }
    }

    public void createDeviceServer() {

        if (installationToken == null) {
            throw new IllegalStateException("Please perform installation first!");
        }

        final String body = String.format("{\"description\": \"Leandro Main Device\", \"secret\": \"%s\"}", apiKey);
        final String requestId = UUID.randomUUID().toString();

        LOGGER.debug("Creating DeviceServer");
        LOGGER.debug("Sending body: {}", body);

        final String signature = getBase64Signature("POST /v1/device-server", installationToken, requestId, body, privateKey);

        try {
            final HttpResponse<JsonNode> jsonResponse = Unirest.post(String.format("%s/device-server", BUNQ_API_URI))
                    .header(CACHE_CONTROL_HEADER, NO_CACHE)
                    .header(USER_AGENT_HEADER, USER_AGENT)
                    .header(BUNQ_CLIENT_AUTHENTICATION_HEADER, installationToken)
                    .header(BUNQ_CLIENT_SIGNATURE_HEADER, signature)
                    .header(BUNQ_CLIENT_REQUEST_ID_HEADER, requestId)
                    .header(BUNQ_GEOLOCATION_HEADER, NO_GEOLOCATION)
                    .header(BUNQ_LANGUAGE_HEADER, EN_US)
                    .header(BUNQ_REGION_HEADER, EN_US)
                    .body(body)
                    .asJson();

            LOGGER.debug("DeviceServer creation response code: {}", jsonResponse.getStatus());
            LOGGER.debug("DeviceServer creation response body: {}", jsonResponse.getBody().toString());

            verifyServerSignature(jsonResponse, serverPublicKey);

        } catch (final UnirestException e) {
            LOGGER.error("Problem when creating DeviceServer", e);
        }
    }

    public void login() {

        LOGGER.debug("Creating a session...");

        if (installationToken == null) {
            throw new IllegalStateException("Please perform installation first!");
        }

        final String requestId = UUID.randomUUID().toString();
        final String body = String.format("{\"secret\": \"%s\"}", apiKey);

        final String signature = getBase64Signature("POST /v1/session-server", installationToken, requestId, body, privateKey);

        try {
            final HttpResponse<JsonNode> jsonResponse = Unirest.post(String.format("%s/session-server", BUNQ_API_URI))
                    .header(CACHE_CONTROL_HEADER, NO_CACHE)
                    .header(USER_AGENT_HEADER, USER_AGENT)
                    .header(BUNQ_CLIENT_AUTHENTICATION_HEADER, installationToken)
                    .header(BUNQ_CLIENT_SIGNATURE_HEADER, signature)
                    .header(BUNQ_CLIENT_REQUEST_ID_HEADER, requestId)
                    .header(BUNQ_GEOLOCATION_HEADER, NO_GEOLOCATION)
                    .header(BUNQ_LANGUAGE_HEADER, EN_US)
                    .header(BUNQ_REGION_HEADER, EN_US)
                    .body(body)
                    .asJson();

            LOGGER.debug("Session Creation response code: {}", jsonResponse.getStatus());
            LOGGER.debug("Session Creation response body: {}", jsonResponse.getBody().toString());

            final JSONArray response = (JSONArray) jsonResponse.getBody().getObject().get("Response");
            final JSONObject tokenDetails = (JSONObject) ((JSONObject) response.get(1)).get("Token");
            final JSONObject userCompanyDetails = (JSONObject) ((JSONObject) response.get(2)).get("UserCompany");

            verifyServerSignature(jsonResponse, serverPublicKey);

            sessionToken = tokenDetails.getString("token");
            loggedUserId = userCompanyDetails.getInt("id");

        } catch (final UnirestException e) {
            LOGGER.error("Problem when creating a Session", e);
        }
    }

    public void getMonetaryAccounts() {

        LOGGER.debug("Getting Monetary Accounts...");

        if (sessionToken == null) {
            throw new IllegalStateException("Please login first!");
        }

        final String requestId = UUID.randomUUID().toString();

        final String signature = getBase64Signature(String.format("GET /v1/user/%s/monetary-account", loggedUserId), sessionToken, requestId, "", privateKey);

        LOGGER.debug("Request Signature {}", signature);

        try {
            final HttpResponse<JsonNode> jsonResponse = Unirest.get(String.format("%s/user/%d/monetary-account", BUNQ_API_URI, loggedUserId))
                    .header(CACHE_CONTROL_HEADER, NO_CACHE)
                    .header(USER_AGENT_HEADER, USER_AGENT)
                    .header(BUNQ_CLIENT_AUTHENTICATION_HEADER, sessionToken)
                    .header(BUNQ_CLIENT_SIGNATURE_HEADER, signature)
                    .header(BUNQ_CLIENT_REQUEST_ID_HEADER, requestId)
                    .header(BUNQ_GEOLOCATION_HEADER, NO_GEOLOCATION)
                    .header(BUNQ_LANGUAGE_HEADER, EN_US)
                    .header(BUNQ_REGION_HEADER, EN_US)
                    .asJson();

            LOGGER.debug("Monetary Accounts response code: {}", jsonResponse.getStatus());
            debugResponseHeaders(jsonResponse);
            LOGGER.debug("Monetary response body: {}", jsonResponse.getBody().toString());

            verifyServerSignature(jsonResponse, serverPublicKey);

        } catch (final UnirestException e) {
            LOGGER.error("Problem fetching Monetary Accounts", e);
        }

    }

    public void listInstallations() {

        LOGGER.debug("Getting Current Installations...");

        final String requestId = UUID.randomUUID().toString();
        final String signature = getBase64Signature("GET /v1/installation", sessionToken, requestId, "", privateKey);

        try {
            final HttpResponse<JsonNode> jsonResponse = Unirest.get(String.format("%s/installation", BUNQ_API_URI))
                    .header(CACHE_CONTROL_HEADER, NO_CACHE)
                    .header(USER_AGENT_HEADER, USER_AGENT)
                    .header(BUNQ_CLIENT_AUTHENTICATION_HEADER, sessionToken)
                    .header(BUNQ_CLIENT_SIGNATURE_HEADER, signature)
                    .header(BUNQ_CLIENT_REQUEST_ID_HEADER, requestId)
                    .header(BUNQ_GEOLOCATION_HEADER, NO_GEOLOCATION)
                    .header(BUNQ_LANGUAGE_HEADER, EN_US)
                    .header(BUNQ_REGION_HEADER, EN_US)
                    .asJson();

            LOGGER.debug("Current Installations response code: {}", jsonResponse.getStatus());
            debugResponseHeaders(jsonResponse);
            LOGGER.debug("Current Installations  body: {}", jsonResponse.getBody().toString());

            verifyServerSignature(jsonResponse, serverPublicKey);

        } catch (final UnirestException e) {
            LOGGER.error("Problem when fetching Installations", e);
        }
    }

    private static String getBase64Signature(final String action, final String authenticationToken, final String requestId, final String body, final byte[] privateKeyBytes) {

        final StringBuilder dataToSign = new StringBuilder();
        dataToSign.append(action);
        dataToSign.append(LINE_FEED);
        dataToSign.append("Cache-Control: no-cache\n");
        dataToSign.append("User-Agent: ");
        dataToSign.append(USER_AGENT);
        dataToSign.append(LINE_FEED);
        dataToSign.append("X-Bunq-Client-Authentication: ");
        dataToSign.append(authenticationToken);
        dataToSign.append(LINE_FEED);
        dataToSign.append("X-Bunq-Client-Request-Id: ");
        dataToSign.append(requestId);
        dataToSign.append(LINE_FEED);
        dataToSign.append("X-Bunq-Geolocation: 0 0 0 0 000\n");
        dataToSign.append("X-Bunq-Language: en_US\n");
        dataToSign.append("X-Bunq-Region: en_US");
        dataToSign.append("\n\n");
        dataToSign.append(body);

        try {

            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final KeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            final Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(dataToSign.toString().getBytes());

            return DatatypeConverter.printBase64Binary(signature.sign());

        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {

            LOGGER.error("Failed to generate signature", e);

            return null;
        }
    }

    public static KeyPair generateRSA2048KeyPair() {

        try {

            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.genKeyPair();

        } catch (final NoSuchAlgorithmException e) {
            LOGGER.error("Failed to generate RSA 2048 Key Pair", e);
            return null;
        }

    }

    private static void verifyServerSignature(final HttpResponse response, final byte[] serverPublicKey) {

        final List<BunqHeader> headersToVerify = new ArrayList<>();

        for (final Map.Entry<String, List<String>> e : response.getHeaders().entrySet()) {
            if (e.getKey().startsWith(BUNQ_HEADER_PREFIX) && !BUNQ_SERVER_SIGNATURE.equals(e.getKey())) {
                headersToVerify.add(new BunqHeader(e.getKey(), e.getValue().get(0)));
            }
        }

        Collections.sort(headersToVerify, new Comparator<BunqHeader>() {
            @Override
            public int compare(final BunqHeader o1, final BunqHeader o2) {
                return o1.getHeader().compareTo(o2.getHeader());
            }
        });

        final StringBuilder dataToSign = new StringBuilder();
        dataToSign.append(response.getStatus());
        dataToSign.append(LINE_FEED);

        for (final BunqHeader h : headersToVerify) {
            dataToSign.append(h.toString());
        }

        try {

            dataToSign.append(LINE_FEED);
            dataToSign.append(IOUtils.toString(response.getRawBody(), Charset.defaultCharset()));

            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final KeySpec serverPublicKeySpec = new X509EncodedKeySpec(serverPublicKey);
            final PublicKey publicKey = keyFactory.generatePublic(serverPublicKeySpec);

            final Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(dataToSign.toString().getBytes());

            final String serverSignature = response.getHeaders().getFirst(BUNQ_SERVER_SIGNATURE);

            final boolean verified = signature.verify(DatatypeConverter.parseBase64Binary(serverSignature));

            LOGGER.debug("Server Signature Verified: {}", verified);

        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException | IOException e) {
            LOGGER.error("Failed to verify response", e);
        }

    }

    private static void debugResponseHeaders(final HttpResponse response) {

        LOGGER.debug("---------- Headers received in response ----------");

        for (final Map.Entry<String, List<String>> e : response.getHeaders().entrySet()) {
            LOGGER.debug("{}: {}", e.getKey(), e.getValue().get(0));
        }

        LOGGER.debug("--------------------------------------------------");
    }

    private static class BunqHeader {

        private final String header;
        private final String value;

        BunqHeader(final String header, final String value) {
            this.header = header;
            this.value = value;
        }

        String getHeader() {
            return header;
        }

        @Override
        public String toString() {
            return String.format("%s: %s%n", header, value);
        }

    }

}
