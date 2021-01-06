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

import burp.BurpExtender;
import burp.IHttpService;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import ui.Evidencer;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.*;

import static ui.Evidencer.*;

/**
 * Burp extension - Evidencer
 * <p>
 * Define some constant attributes and utility functions.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class Utils {

    // OWASP objectives
    public static final String A1 = "A1 - Injection";
    public static final String A2 = "A2 - Broken Authentication";
    public static final String A3 = "A3 - Sensitive Data Exposure";
    public static final String A4 = "A4 - XML External Entities (XXE)";
    public static final String A5 = "A5 - Broken Access Control";
    public static final String A6 = "A6 - Security Misconfiguration";
    public static final String A7 = "A7 - Cross-Site Scripting (XSS)";
    public static final String A8 = "A8 - Insecure Deserialization";
    public static final String A9 = "A9 - Using Components with Known Vulnerabilities";
    public static final String A10 = "A10 - Insufficient Logging and Monitoring";

    // Icons for the buttons in the UI
    public static final String VULN_DB_CSV = "/vuln_db.csv";
    public static final String PANEL_DEFAULT = "/panel_defaults.png";
    public static final String PANEL_MINUS = "/panel_minus.png";
    public static final String PANEL_PLUS = "/panel_plus.png";
    public static final String LOAD = "/load.png";
    public static final String SAVE = "/save.png";
    public static final String NEW = "/new.png";
    public static final String PREV = "/prev.png";
    public static final String NEXT = "/next.png";

    // String separator for the CWEs and their descriptions
    public static final String SEPARATOR = "###";

    // Colors for text/background
    public static final String WHITE_COLOR = "white";
    public static final String BLACK_COLOR = "black";
    public static final String RED_COLOR = "red";
    // Column number of evidence attributes in the JTable
    public static final int HIGHLIGHT_COLUMN = 0;
    public static final int COMMENT_COLUMN = 10;
    public static final int TO_COLUMN = 11;
    public static final int CWE_COLUMN = 12;
    public static final int DESCRIPTION_COLUMN = 13;
    public static final int ATTACK_SUCCESSFUL_COLUMN = 14;
    public static final List<String> OBJECTIVES = Arrays.asList(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10);
    public static final Color[] COLORS = {Color.BLUE, Color.CYAN, Color.GRAY, Color.GREEN, Color.MAGENTA,
            Color.ORANGE, Color.PINK, Color.RED, Color.WHITE, Color.YELLOW};
    public static final List<String> COLORS_STRING = Arrays.asList("blue", "cyan", "gray", "green", "magenta",
            "orange", "pink", "red", "white", "yellow");
    // Define the maximum size of the redo/undo lists, to not pollute memory
    private static final int MAX_SIZE = 50;
    // Gson parser for serializing / deserializing evidences
    private static final Gson gson = new Gson();
    // To save the state of the extension
    public static String LOGFILE;
    // Default path in witch the popup for loading/saving will prompt the user
    // Will be replaced by the last user browsed directory
    private static File LOAD_SAVE_LOCATION = new File(System.getProperty("user.home"));

    /**
     * Return a Color for a given string
     *
     * @param color the color string
     * @return the Color object
     */
    public static Color getColorFromString(String color) {
        int index = COLORS_STRING.indexOf(color);
        return index == -1 ? Color.BLACK : COLORS[index];
    }

    /**
     * Return the appropriate font color given a specific color
     * If the color is blue or red, then the font should be white for better readability
     *
     * @param color the background color of the evidence
     * @return the color for the font in the evidence
     */
    public static String getForegroundColorFromHighlightColor(String color) {
        return (getColorFromString(color) == Color.RED ||
                getColorFromString(color) == Color.BLUE)
                ? WHITE_COLOR
                : BLACK_COLOR;
    }

    /**
     * Parse the date at which the server replied so that we can keep track of time in the extension
     *
     * @param response the server's response
     * @return the server's response's date
     */
    static String getDateFromResponse(byte[] response) {
        String res = new String(response);
        String date = "";
        int start = res.indexOf("Date: ");
        if (start != -1) {
            int end = res.indexOf("\n", start);
            if (end != -1) {
                date = res.substring(start, end)
                        .replace("Date: ", "")
                        .replace(",", "")
                        .trim();
            }
        }
        SimpleDateFormat parser = new SimpleDateFormat("EEE d MMM yyyy HH:mm:ss zzz");
        try {
            return parser.parse(date).toString();
        } catch (ParseException e) {
            BurpExtender.stderr.println(e.getMessage());
        }
        return date;
    }

    /**
     * Make sure we are not pushing twice the same data to the undo/redo structures (e.g. when changing the CWE to the
     * exact same)
     *
     * @param element    the element that we want to push to the linked list
     * @param linkedList the undo or redo linked list
     */
    public static void peekAndPushOrDoNothing(Object[] element, LinkedList<Object[]> linkedList) {
        Object[] mostRecent = linkedList.peek();
        if (!Arrays.equals(mostRecent, element)) {
            if (linkedList.size() == Utils.MAX_SIZE) linkedList.removeLast(); // Prevent for overgrowing
            linkedList.push(element);
        }
    }

    /**
     * Redo an action that was undone
     */
    public static void redoAction() {
        try {
            Object[] next = Evidencer.redo.pop();
            if (next[0] instanceof ArrayList) {
                // Add / remove evidence back
                if (next[1].equals("added")) {
                    httpRequestResponses.addAll((Collection<? extends HttpRequestResponse>) next[0]);
                } else {
                    httpRequestResponses.removeAll((Collection<? extends HttpRequestResponse>) next[0]);
                }
                // Save it to the undo stack
                Utils.peekAndPushOrDoNothing(next,
                        Evidencer.undo
                );
                // Refresh the UI
                evidencerTableModel.fireTableDataChanged();
                // Save to log file
                Utils.saveToLogFile(Utils.LOGFILE, false);
            } else {
                int index = Integer.valueOf(next[1].toString());
                // Save it to the undo stack
                Utils.peekAndPushOrDoNothing(new Object[]{httpRequestResponses.get(index), index},
                        Evidencer.undo
                );
                httpRequestResponses.set(index, (HttpRequestResponse) next[0]);
                // Refresh the UI
                evidencerTableModel.fireTableDataChanged();
                // Save to log file
                Utils.saveToLogFile(Utils.LOGFILE, false);
            }
        } catch (NoSuchElementException e) {
            BurpExtender.stderr.println(e.getMessage());
        }
    }

    /**
     * Undo an action that was done
     */
    public static void undoAction() {
        try {
            Object[] prev = Evidencer.undo.pop();
            if (prev[0] instanceof ArrayList) {
                // Remove / add evidence back
                if (prev[1].equals("added")) {
                    httpRequestResponses.removeAll((Collection<? extends HttpRequestResponse>) prev[0]);
                } else {
                    httpRequestResponses.addAll((Collection<? extends HttpRequestResponse>) prev[0]);
                }
                // Save it to the redo stack
                Utils.peekAndPushOrDoNothing(prev,
                        Evidencer.redo
                );
                // Refresh the UI
                evidencerTableModel.fireTableDataChanged();
                // Save to log file
                Utils.saveToLogFile(Utils.LOGFILE, false);
            } else {
                int index = Integer.valueOf(prev[1].toString());
                // Save it to the undo stack
                HttpRequestResponse oldEvidence = httpRequestResponses.get(index);
                Utils.peekAndPushOrDoNothing(new Object[]{oldEvidence, index},
                        Evidencer.redo
                );
                httpRequestResponses.set(index, (HttpRequestResponse) prev[0]);
                // Refresh the UI
                evidencerTableModel.fireTableDataChanged();
                // Save to log file
                Utils.saveToLogFile(Utils.LOGFILE, false);
            }
        } catch (NoSuchElementException e) {
            BurpExtender.stderr.println(e.getMessage());
        }
    }

    /**
     * Saves the state of the extension (i.e. the evidences) to a file
     *
     * @param path the path to the file
     */
    public static void saveToLogFile(String path, boolean sentFromMenu) {
        // Due to Burp's interface, entries are not serializable as is, so for each entry we need to save the full
        // request / response / other attributes to reconstruct it later and serialize this
        // Since we can modify requests any time, we need to go through all of them each time we log, to get the latest
        // information.

        File logfile = new File(path);
        if (!logfile.exists()) newProjectFile(sentFromMenu);
        path = Utils.LOGFILE;
        logfile = new File(path);

        // Now that we know where to save the file, save the evidence
        ArrayList<Object[]> serializableEntries = new ArrayList<>();
        httpRequestResponses.forEach(requestResponse -> {
            IHttpService service = requestResponse.service;
            String host = service.getHost();
            int port = service.getPort();
            String protocol = service.getProtocol();
            // Storing in ISO_8859_1 encoding for 1-to-1 match with byte arrays
            String request = new String(requestResponse.request, StandardCharsets.ISO_8859_1);
            String response = new String(requestResponse.response, StandardCharsets.ISO_8859_1);
            String comment = requestResponse.comment;
            String objective = requestResponse.objective;
            String cwe = requestResponse.cwe;
            String description = requestResponse.description;
            String highlight = requestResponse.highlight;
            String fontColor = requestResponse.foregroundColor;
            String attackWasSuccessful = String.valueOf(requestResponse.attackWasSuccessful);
            serializableEntries.add(new Object[]{host, port, protocol, request, response, comment,
                    objective, cwe, description, highlight, fontColor, attackWasSuccessful});
        });
        // Now we can serialize our entries
        String state = gson.toJson(serializableEntries);
        try (PrintWriter out = new PrintWriter(logfile)) {
            out.println(state);
        } catch (FileNotFoundException e) {
            BurpExtender.stderr.println(e.getMessage());
        }
    }

    /**
     * If opening burp or loading the extension, look for a log file and restore data.
     *
     * @param path the path to the log file
     */
    public static void loadExisting(String path) {
        ArrayList<HttpRequestResponse> existingEvidences = new ArrayList<>();
        if (path != null) {
            if (!path.isEmpty()) {
                File logfile = new File(path);
                if (logfile.exists()) {
                    try {
                        String entries = new String(Files.readAllBytes(Paths.get(logfile.toURI())));
                        Type listType = new TypeToken<ArrayList<Object[]>>() {}.getType();
                        ArrayList<Object[]> serializableEntries = gson.fromJson(entries, listType);
                        if (serializableEntries != null) {
                            if (serializableEntries.size() != 0) {
                                // Reinit initial ids
                                HttpRequestResponse.setNewId(1);
                                serializableEntries.forEach(entry -> {
                                    // Each entry is an Object[] host, port, protocol, request, response, comment, objective,
                                    // cwe, risk, highlight, foregroundColor, attackWasSuccessful
                                    try {
                                        // Retrieving entry info
                                        String host = entry[0].toString();
                                        int port = Double.valueOf(entry[1].toString()).intValue();
                                        String protocol = entry[2].toString();
                                        byte[] request = entry[3].toString().getBytes(StandardCharsets.ISO_8859_1);
                                        byte[] response = entry[4].toString().getBytes(StandardCharsets.ISO_8859_1);
                                        String comment = entry[5] == null ? "" : entry[5].toString();
                                        String objective = entry[6].toString();
                                        String cwe = entry[7] == null ? "" : entry[7].toString();
                                        String risk = entry[8] == null ? "" : entry[8].toString();
                                        String highlight = entry[9].toString();
                                        String fontColor = entry[10].toString();
                                        boolean attackWasSuccessful = Boolean.valueOf(entry[11].toString());

                                        // Building back proper burp struct
                                        IHttpService service = BurpExtender.helpers.buildHttpService(host, port, protocol);
                                        HttpRequestResponse requestResponse = new HttpRequestResponse
                                                .HttpRequestResponseBuilder(service, request, response)
                                                .withComment(comment)
                                                .withObjective(objective)
                                                .withCwe(cwe)
                                                .withDescription(risk)
                                                .withHighlight(highlight)
                                                .withForegroundColor(fontColor)
                                                .withAttackSuccessful(attackWasSuccessful)
                                                .build();
                                        existingEvidences.add(requestResponse);
                                    } catch (ArrayIndexOutOfBoundsException e) {
                                        BurpExtender.stderr.println("Could not restore state, most likely due to a corrupted log file.");
                                    }
                                });
                            }
                        }
                    } catch (IOException | JsonSyntaxException e) {
                        BurpExtender.stderr.println("Log file not recognized");
                        BurpExtender.stderr.println(e.getMessage());
                    }
                    // If this was successful, then we set the default log file to whatever path was given
                    Utils.LOGFILE = path;
                    // Save this setting in burp
                    BurpExtender.callbacks.saveExtensionSetting("logfile", Utils.LOGFILE);
                }
            }
        }
        httpRequestResponses = existingEvidences;
        if (evidencerTableModel != null) {
            // Refresh UI
            evidencerTableModel.fireTableDataChanged();
        }
    }

    /**
     * Prompts the user to pick a file from which to load evidences
     */
    public static void loadExistingFromFile() {
        // Prompt user to pick a file to load data from
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(Utils.LOAD_SAVE_LOCATION);
        fileChooser.setDialogTitle("Choose a file where to load the evidences from");
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            // Saving last browsed location
            Utils.LOAD_SAVE_LOCATION = selectedFile.getParentFile();
            loadExisting(selectedFile.getAbsolutePath());
        }
    }

    /**
     * Prompts the user to save evidences to some file of his choosing
     */
    public static void saveToFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(Utils.LOAD_SAVE_LOCATION);
        fileChooser.setDialogTitle("Choose a file where to save the evidences");
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            // Saving last browsed location
            Utils.LOAD_SAVE_LOCATION = selectedFile.getParentFile();
            // Make a copy of the current log file to wherever the user pointed to
            try {
                Files.copy(Paths.get(Utils.LOGFILE), Paths.get(selectedFile.getAbsolutePath()), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                BurpExtender.stderr.println(e.getMessage());
            }
        }
    }

    /**
     * Create a new evidence file to save entries
     *
     * @param sentFromMenu true if this method is invoked following sending an evidence to the extension
     */
    public static void newProjectFile(boolean sentFromMenu) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(Utils.LOAD_SAVE_LOCATION);
        fileChooser.setDialogTitle("Choose a file where to save the evidences");
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            // Create the file if it does not exist
            if (!selectedFile.exists()) {
                try {
                    boolean fileCreated = selectedFile.createNewFile();
                    if (!fileCreated) {
                        BurpExtender.stderr.println("Could not create file: " + selectedFile);
                    }
                } catch (IOException e) {
                    BurpExtender.stderr.println(e.getMessage());
                }
                // If the file did not exist, we should clear the view except for the last entry if it was sent from
                // the menu
                if (sentFromMenu) {
                    HttpRequestResponse requestResponse = httpRequestResponses.get(httpRequestResponses.size() - 1);
                    httpRequestResponses = new ArrayList<>();
                    httpRequestResponses.add(requestResponse);
                    evidencerTableModel.fireTableDataChanged();
                }
            }
            // Saving last browsed location
            Utils.LOAD_SAVE_LOCATION = selectedFile.getParentFile();
            // Set new log file location
            Utils.LOGFILE = selectedFile.getAbsolutePath();
            // Save this setting in burp
            BurpExtender.callbacks.saveExtensionSetting("logfile", Utils.LOGFILE);
            // Emptying current evidences
            if (!sentFromMenu) {
                httpRequestResponses = new ArrayList<>();
                evidencerTableModel.fireTableDataChanged();
            }
        }
    }

}
