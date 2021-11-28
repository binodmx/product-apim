/*
 * WSO2 API Manager - Developer Portal
 * This document specifies a **RESTful API** for WSO2 **API Manager** - **Developer Portal**. Please see [full OpenAPI Specification](https://raw.githubusercontent.com/wso2/carbon-apimgt/v6.7.206/components/apimgt/org.wso2.carbon.apimgt.rest.api.store.v1/src/main/resources/devportal-api.yaml) of the API which is written using [OAS 3.0](http://swagger.io/) specification.  # Authentication The Developer Portal REST API is protected using OAuth2 and access control is achieved through scopes. Before you start invoking the API, you need to obtain an access token with the required scopes. This guide will walk you through the steps that you will need to follow to obtain an access token. First you need to obtain the consumer key/secret key pair by calling the dynamic client registration (DCR) endpoint. You can add your preferred grant types in the payload. A Sample payload is shown below. ```   {   \"callbackUrl\":\"www.google.lk\",   \"clientName\":\"rest_api_devportal\",   \"owner\":\"admin\",   \"grantType\":\"client_credentials password refresh_token\",   \"saasApp\":true   } ``` Create a file (payload.json) with the above sample payload, and use the cURL shown below to invoke the DCR endpoint. Authorization header of this should contain the base64 encoded admin username and password. **Format of the request** ```   curl -X POST -H \"Authorization: Basic Base64(admin_username:admin_password)\" -H \"Content-Type: application/json\"   \\ -d @payload.json https://<host>:<servlet_port>/client-registration/v0.17/register ``` **Sample request** ```   curl -X POST -H \"Authorization: Basic YWRtaW46YWRtaW4=\" -H \"Content-Type: application/json\"   \\ -d @payload.json https://localhost:9443/client-registration/v0.17/register ``` Following is a sample response after invoking the above curl. ``` { \"clientId\": \"fOCi4vNJ59PpHucC2CAYfYuADdMa\", \"clientName\": \"rest_api_devportal\", \"callBackURL\": \"www.google.lk\", \"clientSecret\": \"a4FwHlq0iCIKVs2MPIIDnepZnYMa\", \"isSaasApplication\": true, \"appOwner\": \"admin\", \"jsonString\": \"{\\\"grant_types\\\":\\\"client_credentials password refresh_token\\\",\\\"redirect_uris\\\":\\\"www.google.lk\\\",\\\"client_name\\\":\\\"rest_api_devportal\\\"}\", \"jsonAppAttribute\": \"{}\", \"tokenType\": null } ``` Next you must use the above client id and secret to obtain the access token. We will be using the password grant type for this, you can use any grant type you desire. You also need to add the proper **scope** when getting the access token. All possible scopes for devportal REST API can be viewed in **OAuth2 Security** section of this document and scope for each resource is given in **authorization** section of resource documentation. Following is the format of the request if you are using the password grant type. ``` curl -k -d \"grant_type=password&username=<admin_username>&password=<admin_password>&scope=<scopes separated by space>\" \\ -H \"Authorization: Basic base64(cliet_id:client_secret)\" \\ https://<host>:<servlet_port>/oauth2/token ``` **Sample request** ``` curl https://localhost:9443/oauth2/token -k \\ -H \"Authorization: Basic Zk9DaTR2Tko1OVBwSHVjQzJDQVlmWXVBRGRNYTphNEZ3SGxxMGlDSUtWczJNUElJRG5lcFpuWU1h\" \\ -d \"grant_type=password&username=admin&password=admin&scope=apim:subscribe apim:api_key\" ``` Shown below is a sample response to the above request. ``` { \"access_token\": \"e79bda48-3406-3178-acce-f6e4dbdcbb12\", \"refresh_token\": \"a757795d-e69f-38b8-bd85-9aded677a97c\", \"scope\": \"apim:subscribe apim:api_key\", \"token_type\": \"Bearer\", \"expires_in\": 3600 } ``` Now you have a valid access token, which you can use to invoke an API. Navigate through the API descriptions to find the required API, obtain an access token as described above and invoke the API with the authentication header. If you use a different authentication mechanism, this process may change.  # Try out in Postman If you want to try-out the embedded postman collection with \"Run in Postman\" option, please follow the guidelines listed below. * All of the OAuth2 secured endpoints have been configured with an Authorization Bearer header with a parameterized access token. Before invoking any REST API resource make sure you run the `Register DCR Application` and `Generate Access Token` requests to fetch an access token with all required scopes. * Make sure you have an API Manager instance up and running. * Update the `basepath` parameter to match the hostname and port of the APIM instance.  [![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/5bc0161b8aa7e701d7bf) 
 *
 * The version of the OpenAPI document: v2
 * Contact: architecture@wso2.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package org.wso2.am.integration.clients.store.api.v1.dto;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonCreator;
/**
* ApplicationInfoDTO
*/

public class ApplicationInfoDTO {
        public static final String SERIALIZED_NAME_APPLICATION_ID = "applicationId";
        @SerializedName(SERIALIZED_NAME_APPLICATION_ID)
            private String applicationId;

        public static final String SERIALIZED_NAME_NAME = "name";
        @SerializedName(SERIALIZED_NAME_NAME)
            private String name;

        public static final String SERIALIZED_NAME_THROTTLING_POLICY = "throttlingPolicy";
        @SerializedName(SERIALIZED_NAME_THROTTLING_POLICY)
            private String throttlingPolicy;

        public static final String SERIALIZED_NAME_DESCRIPTION = "description";
        @SerializedName(SERIALIZED_NAME_DESCRIPTION)
            private String description;

        public static final String SERIALIZED_NAME_STATUS = "status";
        @SerializedName(SERIALIZED_NAME_STATUS)
            private String status = "";

        public static final String SERIALIZED_NAME_GROUPS = "groups";
        @SerializedName(SERIALIZED_NAME_GROUPS)
            private List<String> groups = null;

        public static final String SERIALIZED_NAME_SUBSCRIPTION_COUNT = "subscriptionCount";
        @SerializedName(SERIALIZED_NAME_SUBSCRIPTION_COUNT)
            private Integer subscriptionCount;

        public static final String SERIALIZED_NAME_ATTRIBUTES = "attributes";
        @SerializedName(SERIALIZED_NAME_ATTRIBUTES)
            private Object attributes;

        public static final String SERIALIZED_NAME_OWNER = "owner";
        @SerializedName(SERIALIZED_NAME_OWNER)
            private String owner;


        public ApplicationInfoDTO applicationId(String applicationId) {
        
        this.applicationId = applicationId;
        return this;
        }

    /**
        * Get applicationId
    * @return applicationId
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "01234567-0123-0123-0123-012345678901", value = "")
    
    public String getApplicationId() {
        return applicationId;
    }


    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }


        public ApplicationInfoDTO name(String name) {
        
        this.name = name;
        return this;
        }

    /**
        * Get name
    * @return name
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "CalculatorApp", value = "")
    
    public String getName() {
        return name;
    }


    public void setName(String name) {
        this.name = name;
    }


        public ApplicationInfoDTO throttlingPolicy(String throttlingPolicy) {
        
        this.throttlingPolicy = throttlingPolicy;
        return this;
        }

    /**
        * Get throttlingPolicy
    * @return throttlingPolicy
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "Unlimited", value = "")
    
    public String getThrottlingPolicy() {
        return throttlingPolicy;
    }


    public void setThrottlingPolicy(String throttlingPolicy) {
        this.throttlingPolicy = throttlingPolicy;
    }


        public ApplicationInfoDTO description(String description) {
        
        this.description = description;
        return this;
        }

    /**
        * Get description
    * @return description
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "Sample calculator application", value = "")
    
    public String getDescription() {
        return description;
    }


    public void setDescription(String description) {
        this.description = description;
    }


        public ApplicationInfoDTO status(String status) {
        
        this.status = status;
        return this;
        }

    /**
        * Get status
    * @return status
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "APPROVED", value = "")
    
    public String getStatus() {
        return status;
    }


    public void setStatus(String status) {
        this.status = status;
    }


        public ApplicationInfoDTO groups(List<String> groups) {
        
        this.groups = groups;
        return this;
        }

    /**
        * Get groups
    * @return groups
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(value = "")
    
    public List<String> getGroups() {
        return groups;
    }


    public void setGroups(List<String> groups) {
        this.groups = groups;
    }


        public ApplicationInfoDTO subscriptionCount(Integer subscriptionCount) {
        
        this.subscriptionCount = subscriptionCount;
        return this;
        }

    /**
        * Get subscriptionCount
    * @return subscriptionCount
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(value = "")
    
    public Integer getSubscriptionCount() {
        return subscriptionCount;
    }


    public void setSubscriptionCount(Integer subscriptionCount) {
        this.subscriptionCount = subscriptionCount;
    }


        public ApplicationInfoDTO attributes(Object attributes) {
        
        this.attributes = attributes;
        return this;
        }

    /**
        * Get attributes
    * @return attributes
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "External Reference ID, Billing Tier", value = "")
    
    public Object getAttributes() {
        return attributes;
    }


    public void setAttributes(Object attributes) {
        this.attributes = attributes;
    }


        public ApplicationInfoDTO owner(String owner) {
        
        this.owner = owner;
        return this;
        }

    /**
        * Get owner
    * @return owner
    **/
        @javax.annotation.Nullable
      @ApiModelProperty(example = "admin", value = "")
    
    public String getOwner() {
        return owner;
    }


    public void setOwner(String owner) {
        this.owner = owner;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
        return true;
        }
        if (o == null || getClass() != o.getClass()) {
        return false;
        }
            ApplicationInfoDTO applicationInfo = (ApplicationInfoDTO) o;
            return Objects.equals(this.applicationId, applicationInfo.applicationId) &&
            Objects.equals(this.name, applicationInfo.name) &&
            Objects.equals(this.throttlingPolicy, applicationInfo.throttlingPolicy) &&
            Objects.equals(this.description, applicationInfo.description) &&
            Objects.equals(this.status, applicationInfo.status) &&
            Objects.equals(this.groups, applicationInfo.groups) &&
            Objects.equals(this.subscriptionCount, applicationInfo.subscriptionCount) &&
            Objects.equals(this.attributes, applicationInfo.attributes) &&
            Objects.equals(this.owner, applicationInfo.owner);
    }

    @Override
    public int hashCode() {
        return Objects.hash(applicationId, name, throttlingPolicy, description, status, groups, subscriptionCount, attributes, owner);
    }


@Override
public String toString() {
StringBuilder sb = new StringBuilder();
sb.append("class ApplicationInfoDTO {\n");
    sb.append("    applicationId: ").append(toIndentedString(applicationId)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    throttlingPolicy: ").append(toIndentedString(throttlingPolicy)).append("\n");
    sb.append("    description: ").append(toIndentedString(description)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    groups: ").append(toIndentedString(groups)).append("\n");
    sb.append("    subscriptionCount: ").append(toIndentedString(subscriptionCount)).append("\n");
    sb.append("    attributes: ").append(toIndentedString(attributes)).append("\n");
    sb.append("    owner: ").append(toIndentedString(owner)).append("\n");
sb.append("}");
return sb.toString();
}

/**
* Convert the given object to string with each line indented by 4 spaces
* (except the first line).
*/
private String toIndentedString(Object o) {
if (o == null) {
return "null";
}
return o.toString().replace("\n", "\n    ");
}

}

