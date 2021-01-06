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
import evidencer.Utils;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * Burp extension - Evidencer
 * <p>
 * Implement a CWE picker to associate findings with the vulnerability database.
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
class CwePicker extends JPanel {

    private final static int CWE = 0;
    private final static int RISK = 1;
    JTextField jtfFilter;
    private JTable jTable;
    private TableRowSorter<TableModel> rowSorter;

    CwePicker(int row, WindowFocusListener listener) {

        // Populating data
        String[] columnNames = {"CWE", "Description"};
        ArrayList<String> db = new ArrayList<>();
        try {
            db = readVulnDb();
        } catch (IOException e) {
            BurpExtender.stderr.println(e.getMessage());
        }
        String[][] data = new String[db.size()][2];
        for (int i = 0; i < db.size(); i++) {
            String[] finding = db.get(i).split(",");
            data[i][0] = finding[0];
            data[i][1] = finding[1];
        }

        // JTable Layout
        DefaultTableModel model = new DefaultTableModelNonEditable(data, columnNames);
        jTable = new JTable(model);
        rowSorter = new TableRowSorter<>(jTable.getModel());
        jtfFilter = new JTextField();
        jTable.setRowSorter(rowSorter);
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel("Search:"), BorderLayout.WEST);
        panel.add(jtfFilter, BorderLayout.CENTER);
        setLayout(new BorderLayout());
        add(panel, BorderLayout.SOUTH);
        JScrollPane scrollPane = new JScrollPane(jTable);
        add(scrollPane, BorderLayout.CENTER);

        // Dynamic search on CWEs
        jtfFilter.getDocument().addDocumentListener(new DocumentListener() {

            @Override
            public void insertUpdate(DocumentEvent e) {
                String text = jtfFilter.getText();
                rowSorter.setRowFilter(text.trim().length() == 0 ? null : RowFilter.regexFilter("(?i)" + text));
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                String text = jtfFilter.getText();
                rowSorter.setRowFilter(text.trim().length() == 0 ? null : RowFilter.regexFilter("(?i)" + text));
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                // Do nothing
            }

        });

        // Sets the evidence fields to the CWE chosen by the user
        jTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) { // If double click
                    int _row = jTable.getRowSorter().convertRowIndexToModel(jTable.rowAtPoint(e.getPoint()));
                    String cwe = data[_row][CWE];
                    String risk = data[_row][RISK];
                    Evidencer.evidencerTableModel.setValueAt(cwe + Utils.SEPARATOR + risk, row, Utils.CWE_COLUMN);
                    listener.windowLostFocus(null); // Close the popup
                }
            }
        });

        // Hook the enter key on the keyboard for ease of use
        String selectEntry = "select";
        KeyStroke enter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0);
        jTable.getInputMap(JTable.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(enter, selectEntry);
        jTable.getActionMap().put(selectEntry, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int _row = jTable.getRowSorter().convertRowIndexToModel(jTable.getSelectedRow());
                String cwe = data[_row][CWE];
                String risk = data[_row][RISK];
                Evidencer.evidencerTableModel.setValueAt(cwe + Utils.SEPARATOR + risk, row, Utils.CWE_COLUMN);
                listener.windowLostFocus(null); // Close the popup
            }
        });

    }

    /**
     * Reads the vulnerability database from the CSV file, to populate the CWE picker
     *
     * @return a list of CWEs
     * @throws IOException if the file could not be found
     */
    private ArrayList<String> readVulnDb() throws IOException {
        BufferedReader csvReader = new BufferedReader(new InputStreamReader(getClass().getResource(Utils.VULN_DB_CSV).openStream()));
        csvReader.readLine(); // Skip header
        ArrayList<String> entries = new ArrayList<>();
        String line;
        while ((line = csvReader.readLine()) != null) {
            entries.add(line);
        }
        csvReader.close();
        return entries;
    }

    /**
     * Default Table Model but with non editable cells
     */
    private class DefaultTableModelNonEditable extends DefaultTableModel {

        DefaultTableModelNonEditable(Object[][] data, String[] columnNames) {
            super(data, columnNames);
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    }

}
