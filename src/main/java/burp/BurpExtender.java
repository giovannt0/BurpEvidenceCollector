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

package burp;

import ui.EvidencerMenu;
import ui.Evidencer;

import javax.swing.*;
import java.io.PrintWriter;

/**
 * Burp extension - Evidencer
 * <p>
 * Evidencer makes storing and sorting evidences acquired during penetration tests easy.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class BurpExtender implements IBurpExtender {

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static void main(final String[] args) {
        // This is required for the jar file
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        // Set extension
        BurpExtender.callbacks.setExtensionName("Evidencer");
        BurpExtender.callbacks.printOutput("Evidencer - Easily classify your findings");
        BurpExtender.callbacks.printOutput("Created by Theo Giovanna - https://github.com/giovannt0");

        // Set output streams
        stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
        stderr = new PrintWriter(BurpExtender.callbacks.getStderr(), true);

        // Set UI
        SwingUtilities.invokeLater(new Evidencer());

        // Set menu
        BurpExtender.callbacks.registerContextMenuFactory(new EvidencerMenu());

    }

}