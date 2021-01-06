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
import burp.IHttpService;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.stream.IntStream;

/**
 * Burp extension - Evidencer
 * <p>
 * Popup menu that is displayed when right clicking on an evidence, e.g. to send the request back to repeater
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class EvidencerTablePopup extends JPopupMenu {

    final Separator scopeSeparator;
    final JMenuItem scopeAdd;
    final JMenuItem scopeExclude;
    private final JMenuItem header;
    private Evidencer evidencer;

    EvidencerTablePopup(Evidencer evidencer) {
        this.evidencer = evidencer;
        header = new JMenuItem();
        scopeSeparator = new Separator();
        scopeAdd = new JMenuItem("Add to scope");
        scopeAdd.addActionListener(e -> {
            for (int i : Evidencer.evidencerTable.getSelectedRows()) {
                BurpExtender.callbacks.includeInScope(Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(i)).url);
            }
        });
        scopeExclude = new JMenuItem("Remove from scope");
        scopeExclude.addActionListener(e -> {
            for (int i : Evidencer.evidencerTable.getSelectedRows()) {
                BurpExtender.callbacks.excludeFromScope(Evidencer.httpRequestResponses.get(Evidencer.evidencerTable.convertRowIndexToModel(i)).url);
            }
        });
        initialize();
    }

    JMenuItem getHeader() {
        return header;
    }

    private void initialize() {
        add(header);
        add(scopeSeparator);
        add(scopeAdd);
        add(scopeExclude);
        add(new Separator());

        JMenuItem doAnActiveScan = new JMenuItem("Do an active scan");
        doAnActiveScan.addActionListener(e -> {
            IHttpService service = evidencer.rightClickPointerEntry.service;
            BurpExtender.callbacks.doActiveScan(service.getHost(), service.getPort(), "https".equals(service.getProtocol()), evidencer.rightClickPointerEntry.request);
        });
        add(doAnActiveScan);
        JMenuItem doAPassiveScan = new JMenuItem("Do a passive scan");
        doAPassiveScan.addActionListener(e -> {
            IHttpService service = evidencer.rightClickPointerEntry.service;
            BurpExtender.callbacks.doPassiveScan(service.getHost(), service.getPort(), "https".equals(service.getProtocol()), evidencer.rightClickPointerEntry.request, evidencer.rightClickPointerEntry.response);
        });
        add(doAPassiveScan);
        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> {
            IHttpService service = evidencer.rightClickPointerEntry.service;
            BurpExtender.callbacks.sendToIntruder(service.getHost(), service.getPort(), "https".equals(service.getProtocol()), evidencer.rightClickPointerEntry.request);
        });
        add(sendToIntruder);
        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            IHttpService service = evidencer.rightClickPointerEntry.service;
            BurpExtender.callbacks.sendToRepeater(service.getHost(), service.getPort(), "https".equals(service.getProtocol()), evidencer.rightClickPointerEntry.request, null);
        });
        add(sendToRepeater);

        add(new Separator());

        JMenuItem deleteSelected = new JMenuItem("Delete selected");
        deleteSelected.addActionListener(e -> {
            int[] rows = Evidencer.evidencerTable.getSelectedRows();
            IntStream.range(0, rows.length).forEach(i -> rows[i] = Evidencer.evidencerTable.convertRowIndexToModel(rows[i]));
            Evidencer.evidencerTableModel.removeAll(rows);
        });
        add(deleteSelected);
        JMenuItem deleteCWE = new JMenuItem("Reinitialise CWE");
        deleteCWE.addActionListener(e -> {
            int[] rows = Evidencer.evidencerTable.getSelectedRows();
            IntStream.range(0, rows.length).forEach(i -> rows[i] = Evidencer.evidencerTable.convertRowIndexToModel(rows[i]));
            Evidencer.evidencerTableModel.removeCWE(rows);
        });
        add(deleteCWE);
        JMenuItem copyURL = new JMenuItem("Copy URL");
        copyURL.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(new StringSelection(evidencer.rightClickPointerEntry.url.toString()), null);
        });
        add(copyURL);
    }
}
