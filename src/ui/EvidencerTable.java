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

import burp.BurpExtender;
import evidencer.HttpRequestResponse;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;

/**
 * Burp extension - Evidencer
 * <p>
 * Main JTable for displaying evidences
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class EvidencerTable extends JTable {

    private Evidencer evidencer;

    EvidencerTable(Evidencer evidencer, TableModel tableModel) {
        super(tableModel);
        this.evidencer = evidencer;
    }

    /**
     * When right clicking, we display only the beginning of the URL and the end of it, so we truncate the middle
     *
     * @param str    the original url string
     * @param middle what to place in the middle
     * @param length the final length we want
     * @return a truncated url e.g. https://url/stuff/.../stuff/?id=2
     */
    private static String abbreviateMiddle(String str, String middle, int length) {
        if (str.length() == 0 || middle.length() == 0 || length >= str.length() || length < middle.length() + 2)
            return str;
        int targetSting = length - middle.length();
        int startOffset = targetSting / 2 + targetSting % 2;
        int endOffset = str.length() - targetSting / 2;
        return str.substring(0, startOffset) +
                middle +
                str.substring(endOffset);

    }

    private void updateResponse() {
        byte[] response = evidencer.chosenHttpRequestResponse.response;
        if (response != null) {
            evidencer.responseViewer.setMessage(evidencer.chosenHttpRequestResponse.response, false);
        } else {
            evidencer.responseViewer.setMessage(new byte[0], false);
        }
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        HttpRequestResponse requestResponse = Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(row));
        evidencer.requestViewer.setMessage(requestResponse.request, true);
        evidencer.chosenHttpRequestResponse = requestResponse;
        updateResponse();
        super.changeSelection(row, col, toggle, extend);
    }

    @Override
    public JPopupMenu getComponentPopupMenu() {
        Point pt = getMousePosition();
        if (pt != null) {
            evidencer.rightClickPointerEntry = Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(rowAtPoint(pt)));
            evidencer.rightClickPopUp.getHeader().setText(abbreviateMiddle(evidencer.rightClickPointerEntry.url.toString(), "...", 70));
        } else {
            evidencer.rightClickPointerEntry = null;
        }
        // scope add/remove options visibility
        int selectedCount = Evidencer.evidencerTable.getSelectedRows().length;
        evidencer.rightClickPopUp.scopeSeparator.setVisible(selectedCount > 0);
        if (selectedCount > 0) {
            if (selectedCount > 1) {
                evidencer.rightClickPopUp.scopeAdd.setVisible(true);
                evidencer.rightClickPopUp.scopeExclude.setVisible(true);
            } else {
                boolean inScope = BurpExtender.callbacks.isInScope(Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(Evidencer.evidencerTable.getSelectedRows()[0])).url);
                evidencer.rightClickPopUp.scopeAdd.setVisible(!inScope);
                evidencer.rightClickPopUp.scopeExclude.setVisible(inScope);
            }
        } else {
            evidencer.rightClickPopUp.scopeAdd.setVisible(false);
            evidencer.rightClickPopUp.scopeExclude.setVisible(false);
        }
        return super.getComponentPopupMenu();
    }
}
