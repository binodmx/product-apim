/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.am.integration.tests.keymanagers;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpStatus;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.am.integration.clients.admin.ApiException;
import org.wso2.am.integration.clients.admin.ApiResponse;
import org.wso2.am.integration.clients.admin.api.dto.KeyManagerCertificatesDTO;
import org.wso2.am.integration.clients.admin.api.dto.KeyManagerDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyDTO;
import org.wso2.am.integration.clients.store.api.v1.dto.ApplicationKeyGenerateRequestDTO;
import org.wso2.am.integration.test.impl.DtoFactory;
import org.wso2.am.integration.test.utils.base.APIMIntegrationConstants;
import org.wso2.am.integration.test.utils.bean.APIRequest;
import org.wso2.am.integration.test.utils.http.HttpRequestUtil;
import org.wso2.am.integration.tests.api.lifecycle.APIManagerLifecycleBaseTest;
import org.wso2.carbon.automation.test.utils.http.client.HttpResponse;

import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;

public class Auth0KeyManagerTestCase extends APIManagerLifecycleBaseTest {
    private final Log log = LogFactory.getLog(Auth0KeyManagerTestCase.class);
    private final String endpointHost = "http://localhost";
    private final String keyManagerName = "Auth0KeyManager";
    private final int upperPortLimit = 9999;
    private int lowerPortLimit = 9950;
    private int endpointPort;
    private String endpointURL;
    private String apiId;
    private String appId;
    private ArrayList<String> grantTypes;
    private ApplicationKeyDTO applicationKeyDTO;
    private String accessToken;
    private WireMockServer wireMockServer;
    private String createApplicationResponse;
    private String createClientGrantResponse;
    private String getClientGrantResponse;
    private String getAccessTokenResponse;
    private String getApplicationResponse;
    private String updateApplicationResponse;

    @BeforeClass(alwaysRun = true)
    public void setEnvironment() throws Exception {
        log.info("Auth0KeyManagerTestCase initiated");
        super.init();

        // Initialize endpoint
        endpointPort = getAvailablePort();
        assertNotEquals(endpointPort, -1, "No available port in the range " + lowerPortLimit + "-" + upperPortLimit);
        endpointURL = endpointHost + ":" + endpointPort;

        // Generate jwt and client secret
        String jwt = generateJwt();
        String clientSecret = generateClientSecret();

        // Load responses
        createApplicationResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "createApplicationResponse.json").replace("<client_secret>", clientSecret);
        createClientGrantResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "createClientGrantResponse.json");
        getAccessTokenResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "getAccessTokenResponse.json").replace("<access_token>", jwt);
        getApplicationResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "getApplicationResponse.json").replace("<client_secret>", clientSecret);
        getClientGrantResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "getClientGrantResponse.json");
        updateApplicationResponse = readFile(getAMResourceLocation() + File.separator + "keyManagers" + File.separator
                + "auth0" + File.separator + "updateApplicationResponse.json").replace("<client_secret>", clientSecret);

        // Start wiremock server
        startWiremockServer();

        // Add Auth0 key manager and disable resident key manager
        addAuth0KeyManager();

        // Create and publish a test API
        createAndPublishTestApi();

        // Create a test application and subscribe to test API
        createTestApplicationAndSubscribeToTestApi();
    }

    @Test(groups = {"wso2.am"}, description = "Generate keys in Auth0 key manager")
    public void testGenerateKeys() throws Exception {
        Map<String, Object> additionalProperties = new LinkedHashMap<>();
        additionalProperties.put("app_type", "regular_web");
        additionalProperties.put("token_endpoint_auth_method", "client_secret_basic");
        additionalProperties.put("audience_of_api", "https://localhost:9443");
        applicationKeyDTO = restAPIStore.generateKeys(appId,
                APIMIntegrationConstants.DEFAULT_TOKEN_VALIDITY_TIME, "",
                ApplicationKeyGenerateRequestDTO.KeyTypeEnum.PRODUCTION, null, grantTypes, additionalProperties,
                keyManagerName);
        assertNotNull(applicationKeyDTO, "Unable to generate keys using Auth0 key manager.");
    }

    @Test(groups = {"wso2.am"}, description = "Update keys in Auth0 key manager", dependsOnMethods = "testGenerateKeys")
    public void testUpdateKeys() throws Exception {
        org.wso2.am.integration.clients.store.api.ApiResponse<ApplicationKeyDTO> updateResponse =
                restAPIStore.updateKeys(appId, ApplicationKeyDTO.KeyTypeEnum.PRODUCTION.toString(), applicationKeyDTO);
        assertEquals(updateResponse.getStatusCode(), HTTP_RESPONSE_CODE_OK,
                "Response code mismatched when updating keys using Auth0 key manager.");
    }

    @Test(groups = {"wso2.am"}, description = "Generate access token in Auth0 key manager",
            dependsOnMethods = "testUpdateKeys")
    public void testGenerateAccessToken() {
        accessToken = Objects.requireNonNull(applicationKeyDTO.getToken()).getAccessToken();
        assertNotNull(accessToken, "Unable to generate access token using Auth0 key manager");
    }

    @Test(groups = {"wso2.am"}, description = "Invoke API using generated access token",
            dependsOnMethods = "testGenerateAccessToken")
    public void testInvokeApiWithAccessToken() throws Exception {
        Map<String, String> invokeAPIRequestHeaders = new HashMap<>();
        invokeAPIRequestHeaders.put("accept", "*/*");
        invokeAPIRequestHeaders.put("Authorization", "Bearer " + accessToken);
        HttpResponse invokeAPIResponse = HttpRequestUtil.doGet(getAPIInvocationURLHttp(API_CONTEXT,
                API_VERSION_1_0_0) + "/test", invokeAPIRequestHeaders);
//        assertEquals(invokeAPIResponse.getResponseCode(), HTTP_RESPONSE_CODE_OK,
//                "Unable to invoke API using access token generated by Auth0 key manager.");
    }

    @AfterClass(alwaysRun = true)
    void destroy() throws Exception {
        restAPIStore.deleteApplication(appId);
        restAPIPublisher.deleteAPI(apiId);
        // TODO: remove key manager
        wireMockServer.stop();
    }

    /**
     * Generate jwt
     *
     * @return jwt
     */
    private String generateJwt() {
        long nowMillis = System.currentTimeMillis();
        return Jwts.builder()
                .setIssuedAt(new Date(nowMillis))
                .setExpiration(new Date(nowMillis + 86400))
                .setSubject("sub1@clients")
                .setIssuer(endpointURL + "/")
                .claim("aud", "https://localhost:9443")
                .claim("azp", "client1")
                .claim("scope", "default")
                .claim("gty", "client-credentials")
                .signWith(SignatureAlgorithm.HS256, TextCodec.BASE64.decode("YWRtaW46YWRtaW4="))
                .compact();
    }

    /**
     * Generate client secret
     *
     * @return clientSecret
     */
    private String generateClientSecret() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";
        StringBuilder clientSecret = new StringBuilder();
        while (clientSecret.length() < 64) {
            int index = (int) (Math.random() * characters.length());
            clientSecret.append(characters.charAt(index));
        }
        return clientSecret.toString();
    }

    /**
     * Add Auth0 key manager
     *
     */
    private void addAuth0KeyManager() throws ApiException {
        // Create the key manager DTO with Auth0 key manager type with parameters
        String type = "Auth0";
        String displayName = "Auth0KeyManager";
        String description = "This is Auth0 key manager";
        String introspectionEndpoint = "none";
        String issuer = endpointHost + ":" + endpointPort + "/";
        String revokeEndpoint = endpointHost + ":" + endpointPort + "/oauth/revoke";
        String clientRegistrationEndpoint = endpointHost + ":" + endpointPort + "/oidc/register";
        String tokenEndpoint = endpointHost + ":" + endpointPort + "/oauth/token";
        String authorizeEndpoint = endpointHost + ":" + endpointPort + "/authorize";
        String consumerKeyClaim = "azp";
        String scopesClaim = "scope";
        grantTypes = new ArrayList<>();
        grantTypes.add(APIMIntegrationConstants.GRANT_TYPE.CLIENT_CREDENTIAL);
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("client_id", "clientId");
        jsonObject.addProperty("client_secret", "clientSecret");
        jsonObject.addProperty("audience", endpointURL + "/api/v2/");
        jsonObject.addProperty("self_validate_jwt", true);
        Object additionalProperties = new Gson().fromJson(jsonObject, Map.class);
        String certificateValue = endpointHost + ":" + endpointPort + "/.well-known/jwks.json";
        KeyManagerCertificatesDTO keyManagerCertificates =
                DtoFactory.createKeyManagerCertificatesDTO(KeyManagerCertificatesDTO.TypeEnum.JWKS, certificateValue);
        KeyManagerDTO keyManagerDTO = DtoFactory.createKeyManagerDTO(keyManagerName, description, type, displayName,
                introspectionEndpoint, issuer, clientRegistrationEndpoint, tokenEndpoint, revokeEndpoint, null,
                authorizeEndpoint, null, consumerKeyClaim, scopesClaim, grantTypes, additionalProperties,
                keyManagerCertificates);

        // Add the Auth0 key manager and assert the status code and key manager ID
        ApiResponse<KeyManagerDTO> addedKeyManagers = restAPIAdmin.addKeyManager(keyManagerDTO);
        Assert.assertEquals(addedKeyManagers.getStatusCode(), HttpStatus.SC_CREATED);
        String keyManagerId = addedKeyManagers.getData().getId();
        Assert.assertNotNull(keyManagerId, "The Key Manager ID cannot be null or empty");
    }

    /**
     * Create and publish a test API
     *
     */
    private void createAndPublishTestApi() throws Exception {
        APIRequest apiRequest = new APIRequest(API_NAME, API_CONTEXT, new URL(endpointURL));
        apiRequest.setVersion(API_VERSION_1_0_0);
        apiRequest.setVisibility("public");
        apiRequest.setProvider(user.getUserName());
        List<String> securitySchemes = new ArrayList<>();
        securitySchemes.add("oauth2");
        securitySchemes.add("api_key");
        apiRequest.setSecurityScheme(securitySchemes);
        apiRequest.setTiersCollection(APIMIntegrationConstants.API_TIER.UNLIMITED);
        apiRequest.setTier(APIMIntegrationConstants.API_TIER.UNLIMITED);
        apiId = createAndPublishAPIUsingRest(apiRequest, restAPIPublisher, false);
    }

    /**
     * Create test application and subscribe to test API
     *
     */
    private void createTestApplicationAndSubscribeToTestApi() throws Exception {
        HttpResponse applicationDTO = restAPIStore.createApplication("TestApplication",
                "Test application for Auth0KeyManagerTestCase", APIMIntegrationConstants.APPLICATION_TIER.UNLIMITED,
                ApplicationDTO.TokenTypeEnum.OAUTH);
        appId = applicationDTO.getData();
        restAPIStore.subscribeToAPI(apiId, appId, TIER_UNLIMITED);
    }

    /**
     * Configure and start the wiremock server
     *
     */
    private void startWiremockServer() {
        // Configure APIs and start wiremock server
        wireMockServer = new WireMockServer(options().port(endpointPort));
        wireMockServer.stubFor(WireMock.get(urlEqualTo("/test")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "text/xml")));
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/api/v2/clients")).willReturn(aResponse()
                .withStatus(201).withHeader("Content-Type", "application/json").withBody(createApplicationResponse)));
        wireMockServer.stubFor(WireMock.get(urlEqualTo("/api/v2/clients/client1")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/json").withBody(getApplicationResponse)));
        wireMockServer.stubFor(WireMock.patch(urlEqualTo("/api/v2/clients/client1")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/json").withBody(updateApplicationResponse)));
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/api/v2/client-grants")).willReturn(aResponse()
                .withStatus(201).withHeader("Content-Type", "application/json").withBody(createClientGrantResponse)));
        wireMockServer.stubFor(WireMock.get(urlEqualTo("/api/v2/client-grants")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/json").withBody(getClientGrantResponse)));
        wireMockServer.stubFor(WireMock.post(urlEqualTo("/oauth/token")).willReturn(aResponse()
                .withStatus(200).withHeader("Content-Type", "application/json").withBody(getAccessTokenResponse)));
        wireMockServer.start();
    }

    /**
     * Find a free port to start backend server in given port range
     *
     * @return Available Port Number
     */
    private int getAvailablePort() {
        while (lowerPortLimit < upperPortLimit) {
            if (isPortFree(lowerPortLimit)) {
                return lowerPortLimit;
            }
            lowerPortLimit++;
        }
        return -1;
    }

    /**
     * Check whether given port is available
     *
     * @param port port number
     * @return status
     */
    private boolean isPortFree(int port) {
        Socket s = null;
        try {
            s = new Socket(endpointHost, port);
            return false;
        } catch (IOException e) {
            return true;
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e) {
                    throw new RuntimeException("Unable to close connection ", e);
                }
            }
        }
    }
}
