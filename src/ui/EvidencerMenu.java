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

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import evidencer.HttpRequestResponse;
import evidencer.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a drop down menu to send requests to the extension.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class EvidencerMenu implements IContextMenuFactory, ActionListener {

    private List<IHttpRequestResponse> selectedItems;

    public EvidencerMenu() {

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        // The context refers to where in Burp the right click was called
        byte context = invocation.getInvocationContext();
        // The selected messages array refers to the request that has been right clicked on
        this.selectedItems = Arrays.asList(invocation.getSelectedMessages());

        switch (context) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            case IContextMenuInvocation.CONTEXT_INTRUDER_ATTACK_RESULTS:
            case IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS:
                List<JMenuItem> menu = new ArrayList<>();
                JMenu main = new JMenu("Send to Evidencer");
                // Create the sub-menus
                Utils.OBJECTIVES.forEach(
                        obj -> {
                            JMenuItem item = new JMenuItem(obj);
                            // Set the action command (in this context, the test objective)
                            item.setActionCommand(obj);
                            // Registers the listener
                            item.addActionListener(this);
                            // Add it to the menu
                            main.add(item);
                        }
                );
                menu.add(main);
                return menu;
            default:
                // If we're in a different context, we don't show the menu
                return null;
        }
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // Retrieve the action command associated to the menu item that has been selected
        String objective = e.getActionCommand();
        ArrayList<HttpRequestResponse> newEvidences = new ArrayList<>();
        this.selectedItems.forEach(selected -> {
            String highlight = selected.getHighlight() != null ? selected.getHighlight() : Utils.WHITE_COLOR;
            String foregroundColor = Utils.getForegroundColorFromHighlightColor(highlight);
            // Create an evidence entry
            HttpRequestResponse requestResponse = new HttpRequestResponse
                    .HttpRequestResponseBuilder(selected)
                    .withComment(selected.getComment())
                    .withObjective(objective)
                    .withHighlight(highlight)
                    .withForegroundColor(foregroundColor)
                    .build();
            newEvidences.add(requestResponse);
        });
        // Add new evidences to the extension
        Evidencer.httpRequestResponses.addAll(newEvidences);
        // Add them to the undo stack
        Evidencer.undo.push(new Object[]{newEvidences, "added"});
        // Refresh the UI
        Evidencer.evidencerTableModel.fireTableDataChanged();
        // Save to log file
        Utils.saveToLogFile(Utils.LOGFILE, true);
    }
}
