/*******************************************************************************
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 ******************************************************************************/

package org.wso2.carbon.identity.application.authenticator.kakao;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/***
 * Kakao Custom Authenticator is an outbound authenticator implementation for social login provider named Kakao
 * This extends Oauth Generic Authenticator implementation
 */
public class KakaoCustomAuthenticator extends Oauth2GenericAuthenticator {

    private static final long serialVersionUID = 6614257960044886319L;
    private static final Log logger = LogFactory.getLog(KakaoCustomAuthenticator.class);

    @Override
    public String getFriendlyName() {

        return KakaoCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        return KakaoCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_TOKEN_URL;
    }

    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_AUTH_URL;
    }

    @Override
    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return KakaoCustomAuthenticatorConstants.KAKAO_INFO_URL;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(KakaoCustomAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(KakaoCustomAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(KakaoCustomAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        configProperties.add(callbackUrl);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("Process Authentication Response.");
        }

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CLIENT_SECRET);
            String redirectUri = authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.CALLBACK_URL);
            Boolean basicAuthEnabled = Boolean.parseBoolean(
                    authenticatorProperties.get(Oauth2GenericAuthenticatorConstants.IS_BASIC_AUTH_ENABLED));
            Boolean selfContainedTokenEnabled = Boolean.parseBoolean(authenticatorProperties
                    .get(Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED));
            String code = getAuthorizationCode(request);
            String tokenEP = getTokenEndpoint(authenticatorProperties);
            String token = getToken(tokenEP, clientId, clientSecret, code, redirectUri, basicAuthEnabled);
            String responseBody = getUserInfo(selfContainedTokenEnabled, token, authenticatorProperties);

            if (logger.isDebugEnabled()) {
                logger.debug("Get user info response : " + responseBody);
            }

            buildClaims(context, responseBody);
        } catch (ApplicationAuthenticatorException | MisconfigurationException e) {
            logger.error("Failed to process Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

    }

    protected void buildClaims(AuthenticationContext context, String userInfoString)
            throws ApplicationAuthenticatorException {

        if (userInfoString != null) {
            Map<String, Object> userInfoJson = JSONUtils.parseJSON(userInfoString);
            Object kakaoAccount = userInfoJson.get("kakao_account");
            Map<String, Object> kakaoAccountJson = new HashMap<>();
            if (kakaoAccount != null) {
                kakaoAccountJson = JSONUtils.parseJSON(kakaoAccount.toString());
            }

            Object properties = userInfoJson.get("properties");
            Map<String, Object> propertiesJson = new HashMap<>();
            if (properties != null) {
                propertiesJson = JSONUtils.parseJSON(properties.toString());
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Building claims.");
            }

            Map<ClaimMapping, String> claims = new HashMap<>();
            for (Map.Entry<String, Object> entry : userInfoJson.entrySet()) {
                if ("id".equalsIgnoreCase(entry.getKey())) {
                    claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                            entry.getValue().toString());
                } else if ("kakao_account".equalsIgnoreCase(entry.getKey())) {
                    claims.put(ClaimMapping.build("http://wso2.org/claims/emailaddress",
                                    "http://wso2.org/claims/emailaddress", null, false),
                            kakaoAccountJson.get("email").toString());
                } else if ("properties".equalsIgnoreCase(entry.getKey())) {
                    claims.put(ClaimMapping.build("http://wso2.org/claims/mobile",
                                    "http://wso2.org/claims/mobile", null, false),
                            propertiesJson.get("mobile").toString());
                }
                if (logger.isDebugEnabled()
                        && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
                    logger.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : "
                            + entry.getValue());
                }
            }

            if (StringUtils.isBlank
                    (context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig()
                        .setUserClaimURI(Oauth2GenericAuthenticatorConstants.EMAIL);
            }
            String subjectFromClaims = FrameworkUtils
                    .getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
            if (StringUtils.isNotBlank(subjectFromClaims)) {
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else if (!kakaoAccountJson.isEmpty()) {
                AuthenticatedUser authenticatedUser = AuthenticatedUser
                        .createFederateAuthenticatedUserFromSubjectIdentifier(kakaoAccountJson.get("email").toString());
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, userInfoJson);
            }
            context.getSubject().setUserAttributes(claims);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Decoded json object is null.");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null.");
        }
    }

}

