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

package ui;

import burp.IHttpService;
import burp.IMessageEditorController;

/**
 * Burp extension - Evidencer
 * <p>
 * Used by Burp to display the requests and responses from each evidence
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class EntryEditor implements IMessageEditorController {

    private Evidencer evidencer;

    EntryEditor(Evidencer evidencer) {
        this.evidencer = evidencer;
    }

    @Override
    public IHttpService getHttpService() {
        return evidencer.chosenHttpRequestResponse.service;
    }

    @Override
    public byte[] getRequest() {
        return evidencer.chosenHttpRequestResponse.request;
    }

    @Override
    public byte[] getResponse() {
        return evidencer.chosenHttpRequestResponse.response;
    }

}
