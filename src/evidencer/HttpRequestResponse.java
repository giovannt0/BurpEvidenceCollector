/*
 * Copyright (C) 2020 Theo Giovanna.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package evidencer;

import burp.*;

import java.net.URL;
import java.util.List;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a builder pattern to represent evidences.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class HttpRequestResponse {

    // Custom attributes
    public int id;
    public String method;
    public URL url;
    public boolean hasParams;
    public int paramCount;
    public int status;
    public int length;
    public String mime;
    public String date;
    public String path;
    public String objective;
    public String cwe;
    public String description;
    public String foregroundColor;
    public boolean attackWasSuccessful;

    // Attributes from IHttpRequestResponse Interface
    public IHttpService service;
    public byte[] response;
    public byte[] request;
    public String comment;
    public String highlight;

    // We use the builder pattern, so this constructor can be private
    private HttpRequestResponse() {

    }

    static void setNewId(int id) {
        HttpRequestResponseBuilder.newId = id;
    }

    public static HttpRequestResponse deepCopy(HttpRequestResponse original) {
        return new HttpRequestResponseBuilder(original)
                .withAttackSuccessful(original.attackWasSuccessful)
                .withComment(original.comment)
                .withCwe(original.cwe)
                .withDescription(original.description)
                .withForegroundColor(original.foregroundColor)
                .withHighlight(original.highlight)
                .withObjective(original.objective)
                .build();
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public void setObjective(String objective) {
        this.objective = objective;
    }

    public void setHighlight(String highlight) {
        this.highlight = highlight.toLowerCase();
    }

    public void setForegroundColor(String foregroundColor) {
        this.foregroundColor = foregroundColor;
    }

    public void setAttackWasSuccessful(boolean successful) {
        this.attackWasSuccessful = successful;
    }

    public Object getValueAtColumn(int colIndex) {
        switch (colIndex) {
            case Utils.COMMENT_COLUMN:
                return this.comment;
            case Utils.CWE_COLUMN:
            case Utils.DESCRIPTION_COLUMN:
                return this.cwe + Utils.SEPARATOR + this.description;
            case Utils.TO_COLUMN:
                return this.objective;
            case Utils.ATTACK_SUCCESSFUL_COLUMN:
                return this.attackWasSuccessful;
            case Utils.HIGHLIGHT_COLUMN:
                return this.highlight;
            default:
                return "";
        }
    }

    public static class HttpRequestResponseBuilder implements IHttpRequestResponse {
        // Custom attributes
        private static int newId = 1;
        boolean attackWasSuccessful;
        private int id;
        private String method;
        private URL url;
        private boolean hasParams;
        private int paramCount;
        private int status;
        private int length;
        private String mime;
        private String date;
        private String path;
        private String objective;
        private String cwe;
        private String description;
        private String foregroundColor;
        // Attributes from IHttpRequestResponse Interface
        private IHttpService service;
        private byte[] response;
        private byte[] request;
        private String comment;
        private String highlight;

        // Constructor - from existing IHttpRequestResponse
        public HttpRequestResponseBuilder(IHttpRequestResponse requestResponse) {
            this(requestResponse.getHttpService(), requestResponse.getRequest(), requestResponse.getResponse());
        }

        // Constructor - from existing HttpRequestResponse
        HttpRequestResponseBuilder(HttpRequestResponse requestResponse) {
            this(requestResponse.service, requestResponse.request, requestResponse.response);
        }

        // Constructor - from scratch
        // Response may be null (e.g. if sending from repeater for the first time). If so, we only show minimal
        // information in the evidence.
        HttpRequestResponseBuilder(IHttpService service, byte[] request, byte[] response) {
            this.service = service;
            this.request = request;
            this.response = response;
            this.highlight = Utils.WHITE_COLOR;

            // Filling custom fields
            this.id = HttpRequestResponseBuilder.newId;
            HttpRequestResponseBuilder.newId += 1;
            IRequestInfo infoRequest = BurpExtender.callbacks.getHelpers().analyzeRequest(service, request);
            IResponseInfo infoResponse = response == null ? null : BurpExtender.callbacks.getHelpers().analyzeResponse(response);
            this.method = infoRequest.getMethod();
            this.url = infoRequest.getUrl();
            this.path = this.url.getPath();
            this.hasParams = (this.url.getQuery() != null) || (request.length - infoRequest.getBodyOffset() > 0);
            this.paramCount = this.hasParams ? countParam(infoRequest.getParameters()) : 0;
            this.status = infoResponse == null ? 0 : infoResponse.getStatusCode();
            this.length = infoResponse == null ? 0 : response.length - infoResponse.getBodyOffset();
            this.mime = infoResponse == null ? "" : infoResponse.getStatedMimeType();
            this.date = response == null ? "" : Utils.getDateFromResponse(response);
            this.foregroundColor = Utils.BLACK_COLOR;
            this.attackWasSuccessful = false;
        }

        @Override
        public byte[] getRequest() {
            return this.request;
        }

        @Override
        public void setRequest(byte[] message) {
            this.request = message;
        }

        @Override
        public byte[] getResponse() {
            return this.response;
        }

        @Override
        public void setResponse(byte[] message) {
            this.response = message;
        }

        @Override
        public String getComment() {
            return this.comment;
        }

        @Override
        public void setComment(String comment) {
            this.comment = comment;
        }

        @Override
        public String getHighlight() {
            return this.highlight;
        }

        @Override
        public void setHighlight(String color) {
            this.highlight = color;
        }

        @Override
        public IHttpService getHttpService() {
            return this.service;
        }

        @Override
        public void setHttpService(IHttpService httpService) {
            this.service = httpService;
        }

        private int countParam(List<IParameter> parameterList) {
            int count = 0;
            for (IParameter param : parameterList) {
                if (param.getType() == IParameter.PARAM_BODY || param.getType() == IParameter.PARAM_URL) {
                    count += 1;
                }
            }
            return count;
        }

        public HttpRequestResponseBuilder withComment(String comment) {
            this.comment = comment;
            return this;
        }

        public HttpRequestResponseBuilder withHighlight(String highlight) {
            this.highlight = highlight;
            return this;
        }

        public HttpRequestResponseBuilder withObjective(String objective) {
            this.objective = objective;
            return this;
        }

        HttpRequestResponseBuilder withCwe(String cwe) {
            this.cwe = cwe;
            return this;
        }

        HttpRequestResponseBuilder withDescription(String description) {
            this.description = description;
            return this;
        }

        public HttpRequestResponseBuilder withForegroundColor(String foregroundColor) {
            this.foregroundColor = foregroundColor;
            return this;
        }

        HttpRequestResponseBuilder withAttackSuccessful(boolean successful) {
            this.attackWasSuccessful = successful;
            return this;
        }

        public HttpRequestResponse build() {
            HttpRequestResponse requestResponse = new HttpRequestResponse();
            requestResponse.id = this.id;
            requestResponse.method = this.method;
            requestResponse.url = this.url;
            requestResponse.hasParams = this.hasParams;
            requestResponse.paramCount = this.paramCount;
            requestResponse.status = this.status;
            requestResponse.length = this.length;
            requestResponse.mime = this.mime;
            requestResponse.date = this.date;
            requestResponse.path = this.path;
            requestResponse.objective = this.objective;
            requestResponse.cwe = this.cwe;
            requestResponse.description = this.description;
            requestResponse.foregroundColor = this.foregroundColor;
            requestResponse.service = this.service;
            requestResponse.response = this.response;
            requestResponse.request = this.request;
            requestResponse.comment = this.comment;
            requestResponse.highlight = this.highlight;
            requestResponse.attackWasSuccessful = this.attackWasSuccessful;
            return requestResponse;
        }

    }

}
