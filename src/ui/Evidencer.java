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
import burp.IMessageEditor;
import burp.ITab;
import evidencer.CustomRowSorter;
import evidencer.HttpRequestResponse;
import evidencer.Utils;

import javax.swing.*;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Burp extension - Evidence Collector
 * <p>
 * Implement a simple UI for evidence display.
 * UI design inspired by the awesome flow extension. @hvqzao <https://github.com/hvqzao/burp-flow>
 *
 * @author: Theo Giovanna - https://github.com/giovannt0
 */
public class Evidencer implements Runnable, ITab {

    public static ArrayList<HttpRequestResponse> httpRequestResponses;
    public static LinkedList<Object[]> undo = new LinkedList<>();
    public static LinkedList<Object[]> redo = new LinkedList<>();

    // UI Components
    public static JPanel mainPanel;
    public static EvidencerTableModel evidencerTableModel;
    static EvidencerTable evidencerTable;
    CustomRowSorter<EvidencerTableModel> evidenceTableSorter;
    IMessageEditor requestViewer;
    IMessageEditor responseViewer;
    HttpRequestResponse chosenHttpRequestResponse;
    // Right click menu popup
    EvidencerTablePopup rightClickPopUp;
    HttpRequestResponse rightClickPointerEntry;
    // CWE Picker
    private JDialog cwePickerWindow;
    private boolean cwePickerPopupReady;
    // Filters - Allows you to display requests that were sent to particular test objectives
    private JDialog evidenceFilterPopupWindow;
    private JLabel evidenceFilter;
    private FilterPopup filterPopup;
    private EvidencerWorker evidencerWorker;

    public Evidencer() {
        // Look for logs and if found, restore extension state
        Utils.LOGFILE = BurpExtender.callbacks.loadExtensionSetting("logfile");
        Utils.loadExisting(Utils.LOGFILE);
    }

    @Override
    public void run() {

        ImageIcon iconDefaults = new ImageIcon(new ImageIcon(getClass().getResource(Utils.PANEL_DEFAULT)).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconSelectAll = new ImageIcon(new ImageIcon(getClass().getResource(Utils.PANEL_PLUS)).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconDeselectAll = new ImageIcon(new ImageIcon(getClass().getResource(Utils.PANEL_MINUS)).getImage().getScaledInstance(13, 13, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconLoad = new ImageIcon(new ImageIcon(getClass().getResource(Utils.LOAD)).getImage().getScaledInstance(26, 26, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconSave = new ImageIcon(new ImageIcon(getClass().getResource(Utils.SAVE)).getImage().getScaledInstance(26, 26, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconNew = new ImageIcon(new ImageIcon(getClass().getResource(Utils.NEW)).getImage().getScaledInstance(26, 26, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconPrev = new ImageIcon(new ImageIcon(getClass().getResource(Utils.PREV)).getImage().getScaledInstance(26, 26, java.awt.Image.SCALE_SMOOTH));
        ImageIcon iconNext = new ImageIcon(new ImageIcon(getClass().getResource(Utils.NEXT)).getImage().getScaledInstance(26, 26, java.awt.Image.SCALE_SMOOTH));

        // httpRequestResponses tab prolog: vertical split
        JSplitPane evidenceTab = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        BurpExtender.callbacks.customizeUiComponent(evidenceTab);

        // top: table
        JPanel evidenceTablePane = new JPanel();
        evidenceTablePane.setLayout(new BorderLayout());

        // table
        evidencerTableModel = new EvidencerTableModel();
        evidenceTableSorter = new CustomRowSorter<>(evidencerTableModel);
        evidencerTable = new EvidencerTable(this, evidencerTableModel);
        evidencerTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        evidencerTable.setRowSorter(evidenceTableSorter);

        // Mouse listener for clicking CWE
        evidencerTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = evidencerTable.convertRowIndexToModel(evidencerTable.rowAtPoint(e.getPoint()));
                int col = evidencerTable.convertColumnIndexToModel(evidencerTable.columnAtPoint(e.getPoint()));
                // CWE, Risk
                if (col >= 12 && col <= 13 && e.getClickCount() == 2) {
                    WindowFocusListener listener = new WindowFocusListener() {
                        @Override
                        public void windowLostFocus(WindowEvent e) {
                            cwePickerWindow.setVisible(false);
                            SwingUtilities.invokeLater(() -> cwePickerPopupReady = true);
                        }

                        @Override
                        public void windowGainedFocus(WindowEvent e) {
                        }
                    };
                    cwePickerWindow = new JDialog();
                    CwePicker picker = new CwePicker(row, listener);
                    BurpExtender.callbacks.customizeUiComponent(picker);
                    cwePickerPopupReady = true;
                    cwePickerWindow.add(picker);
                    cwePickerWindow.pack();
                    if (cwePickerPopupReady && !evidenceFilterPopupWindow.isVisible()) {
                        cwePickerPopupReady = false;
                        cwePickerWindow.addWindowFocusListener(listener);
                        // Center the CWE picker with respect to the parent component
                        cwePickerWindow.setLocationRelativeTo(mainPanel);
                        // Place input focus directly in the search field of the CWE picker
                        picker.jtfFilter.requestFocus();
                        cwePickerWindow.setVisible(true);
                    }
                }
            }
        });

        for (int i = 0; i < evidencerTableModel.getColumnCount(); i++) {
            TableColumn column = evidencerTable.getColumnModel().getColumn(i);
            column.setMinWidth(20);
            column.setPreferredWidth(evidencerTableModel.getPreferredWidth(i));
        }

        BurpExtender.callbacks.customizeUiComponent(evidencerTable);
        JScrollPane evidenceTableScroll = new JScrollPane(evidencerTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        evidenceTableScroll.setMinimumSize(new Dimension(40, 40));
        BurpExtender.callbacks.customizeUiComponent(evidenceTableScroll);
        evidencerTable.setDefaultRenderer(Boolean.class, new BooleanTableCellRenderer());
        evidencerTable.getTableHeader().setReorderingAllowed(false);
        evidenceTablePane.add(evidenceTableScroll, BorderLayout.CENTER);
        evidenceTab.setTopComponent(evidenceTablePane);

        // sort index column in descending order
        evidenceTableSorter.toggleSortOrder(0);

        // Right click menu popup
        // evidencerTable popup
        rightClickPopUp = new EvidencerTablePopup(this);
        evidencerTable.setComponentPopupMenu(rightClickPopUp);

        // evidencerTable renderer
        EvidencerTableCellRenderer evidencerTableCellRenderer = new EvidencerTableCellRenderer();
        evidencerTable.setDefaultRenderer(Object.class, evidencerTableCellRenderer);

        // httpRequestResponses bottom prolog: request & response
        JSplitPane evidenceViewPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        evidenceViewPane.setResizeWeight(.5d);
        BurpExtender.callbacks.customizeUiComponent(evidenceViewPane);
        EntryEditor entryEditor = new EntryEditor(this);

        // req
        JPanel requestPane = new JPanel();
        requestPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
        requestPane.setLayout(new BorderLayout());

        evidenceViewPane.setLeftComponent(requestPane);
        requestViewer = BurpExtender.callbacks.createMessageEditor(entryEditor, false);
        requestPane.add(requestViewer.getComponent(), BorderLayout.CENTER);

        // resp
        JPanel responsePane = new JPanel();
        responsePane.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
        responsePane.setLayout(new BorderLayout());

        evidenceViewPane.setRightComponent(responsePane);
        responseViewer = BurpExtender.callbacks.createMessageEditor(entryEditor, false);
        responsePane.add(responseViewer.getComponent(), BorderLayout.CENTER);

        // httpRequestResponses bottom epilog
        evidenceTab.setBottomComponent(evidenceViewPane);
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.X_AXIS));
        mainPanel.add(evidenceTab);

        // filter
        final JPanel evidenceFilterPane = new JPanel();
        evidenceFilterPane.setLayout(new BorderLayout());
        evidenceFilterPane.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        evidenceFilter = new JLabel("Click for filtering options..."); // "Filter: Showing all items");
        evidenceFilter.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(Color.darkGray), BorderFactory.createEmptyBorder(5, 5, 5, 5)));
        evidenceFilterPane.add(evidenceFilter, BorderLayout.CENTER);
        // filter popup
        filterPopup = new FilterPopup();

        // Load file button
        JButton loadEvidenceButton = createJButton(
                iconLoad,
                "Load existing file",
                e -> Utils.loadExistingFromFile()
        );

        // Save file button
        JButton saveEvidenceButton = createJButton(
                iconSave,
                "Save to file",
                e -> Utils.saveToFile()
        );

        // New project button
        JButton newProjectButton = createJButton(
                iconNew,
                "Create a new file",
                e -> Utils.newProjectFile(false)
        );

        // Prev button
        JButton prevButton = createJButton(
                iconPrev,
                "Undo",
                e -> Utils.undoAction()
        );

        // Next button
        JButton nextButton = createJButton(
                iconNext,
                "Redo",
                e -> Utils.redoAction()
        );

        // JPanel containing the files related buttons
        final JPanel loadAndSavePanel = new JPanel();
        loadAndSavePanel.setLayout(new BorderLayout());
        loadAndSavePanel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        loadAndSavePanel.add(loadEvidenceButton, BorderLayout.CENTER);
        loadAndSavePanel.add(saveEvidenceButton, BorderLayout.EAST);
        loadAndSavePanel.add(newProjectButton, BorderLayout.WEST);
        BurpExtender.callbacks.customizeUiComponent(loadAndSavePanel);

        // JPanel containing the prev and next buttons
        final JPanel prevNextPannel = new JPanel();
        prevNextPannel.setLayout(new BorderLayout());
        prevNextPannel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        prevNextPannel.add(prevButton, BorderLayout.WEST);
        prevNextPannel.add(nextButton, BorderLayout.EAST);
        BurpExtender.callbacks.customizeUiComponent(prevNextPannel);

        // JPanel containing all buttons
        final JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BorderLayout());
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        buttonPanel.add(loadAndSavePanel, BorderLayout.WEST);
        buttonPanel.add(prevNextPannel, BorderLayout.EAST);
        BurpExtender.callbacks.customizeUiComponent(buttonPanel);

        // Adding the buttons to the filter pane
        evidenceFilterPane.add(buttonPanel, BorderLayout.EAST);

        // Adding drop down menu for picking testing objectives in case we want to assign an evidence to another T.O
        final TableColumn testingObjective = evidencerTable.getColumn("Test Objective");
        final JComboBox<String> comboBoxObjective = new JComboBox<>();
        for (String OBJECTIVE : Utils.OBJECTIVES) comboBoxObjective.addItem(OBJECTIVE);
        testingObjective.setCellEditor(new DefaultCellEditor(comboBoxObjective));

        // Adding drop down menu for picking evidence highlight
        final TableColumn evidenceId = evidencerTable.getColumn("#");
        final JComboBox<String> comboBoxHighlight = new JComboBox<>();
        for (String COLOR : Utils.COLORS_STRING) comboBoxHighlight.addItem(COLOR);
        ComboBoxRenderer comboBoxRenderer = new ComboBoxRenderer(comboBoxHighlight);
        comboBoxHighlight.setRenderer(comboBoxRenderer);
        evidenceId.setCellEditor(new DefaultCellEditor(comboBoxHighlight));

        // actions
        ActionListener evidenceFilterScopeUpdateAction = e -> {
            if (!filterPopup.evidenceFilterA1Only.isSelected() &&
                    !filterPopup.evidenceFilterA2Only.isSelected() &&
                    !filterPopup.evidenceFilterA3Only.isSelected() &&
                    !filterPopup.evidenceFilterA4Only.isSelected() &&
                    !filterPopup.evidenceFilterA5Only.isSelected() &&
                    !filterPopup.evidenceFilterA6Only.isSelected() &&
                    !filterPopup.evidenceFilterA7Only.isSelected() &&
                    !filterPopup.evidenceFilterA8Only.isSelected() &&
                    !filterPopup.evidenceFilterA9Only.isSelected() &&
                    !filterPopup.evidenceFilterA10Only.isSelected()) {
                filterPopup.evidenceFilterA1OnlyOrigin = filterPopup.evidenceFilterA1.isSelected();
                filterPopup.evidenceFilterA2OnlyOrigin = filterPopup.evidenceFilterA2.isSelected();
                filterPopup.evidenceFilterA3OnlyOrigin = filterPopup.evidenceFilterA3.isSelected();
                filterPopup.evidenceFilterA4OnlyOrigin = filterPopup.evidenceFilterA4.isSelected();
                filterPopup.evidenceFilterA5OnlyOrigin = filterPopup.evidenceFilterA5.isSelected();
                filterPopup.evidenceFilterA6OnlyOrigin = filterPopup.evidenceFilterA6.isSelected();
                filterPopup.evidenceFilterA7OnlyOrigin = filterPopup.evidenceFilterA7.isSelected();
                filterPopup.evidenceFilterA8OnlyOrigin = filterPopup.evidenceFilterA8.isSelected();
                filterPopup.evidenceFilterA9OnlyOrigin = filterPopup.evidenceFilterA9.isSelected();
                filterPopup.evidenceFilterA10OnlyOrigin = filterPopup.evidenceFilterA10.isSelected();
            }
            evidenceFilterUpdate();
        };

        // layout
        evidenceFilterPopupWindow = new JDialog();

        // Filter popup buttons
        JButton evidenceFilterDefaults;
        evidenceFilterDefaults = filterPopup.evidenceFilterDefaults;
        evidenceFilterDefaults.setIcon(iconDefaults);
        BurpExtender.callbacks.customizeUiComponent(evidenceFilterDefaults);
        evidenceFilterDefaults.addActionListener(e -> evidenceFilterSetDefaults());

        JButton evidenceFilterSelectAll;
        evidenceFilterSelectAll = filterPopup.evidenceFilterSelectAll;
        evidenceFilterSelectAll.setIcon(iconSelectAll);
        BurpExtender.callbacks.customizeUiComponent(evidenceFilterSelectAll);
        evidenceFilterSelectAll.addActionListener(e -> evidenceFilterSelectAll());

        JButton evidenceFilterDeselectAll;
        evidenceFilterDeselectAll = filterPopup.evidenceFilterDeselectAll;
        evidenceFilterDeselectAll.setIcon(iconDeselectAll);
        BurpExtender.callbacks.customizeUiComponent(evidenceFilterDeselectAll);
        evidenceFilterDeselectAll.addActionListener(e -> evidenceFilterDeselectAll());

        for (int i = 0; i < filterPopup.evidenceFilters.size(); i++) {
            addActionListenerToEvidenceFilter(
                    filterPopup.evidenceFilters.get(i),
                    filterPopup.evidenceFiltersOnly.get(i),
                    evidenceFilterScopeUpdateAction
            );
        }

        filterPopup.evidenceFilterPopupReady = true;
        evidenceFilterPopupWindow.setUndecorated(true);
        evidenceFilterPopupWindow.add(filterPopup);
        evidenceFilterPopupWindow.pack();
        evidenceFilter.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (filterPopup.evidenceFilterPopupReady) {
                    filterPopup.evidenceFilterPopupReady = false;
                    evidenceFilterPopupWindow.addWindowFocusListener(new WindowFocusListener() {

                        @Override
                        public void windowLostFocus(WindowEvent e) {
                            evidenceFilterPopupWindow.setVisible(false);
                            SwingUtilities.invokeLater(() -> filterPopup.evidenceFilterPopupReady = true);
                        }

                        @Override
                        public void windowGainedFocus(WindowEvent e) {
                        }

                    });
                    Point evidenceFilterPT = evidenceFilter.getLocationOnScreen();
                    evidenceFilterPopupWindow.setLocation(new Point((int) evidenceFilterPT.getX() - 2, evidenceFilterPT.y + evidenceFilter.getHeight() + 1));
                    filterPopup.evidenceFilterBottom.requestFocus();
                    evidenceFilterPopupWindow.setVisible(true);
                }
            }
        });

        evidenceTablePane.add(evidenceFilterPane, BorderLayout.PAGE_START);
        evidenceFilterSetDefaults();
        // Add the extension to burp
        BurpExtender.callbacks.addSuiteTab(this);
    }

    /**
     * Add action to filter check boxes
     *
     * @param evidenceFilter     the objective to filter evidence with
     * @param evidenceFilterOnly if we want to display only one objective
     * @param listener           the action associated to these JCheckBox
     */
    private void addActionListenerToEvidenceFilter(JCheckBox evidenceFilter,
                                                   JCheckBox evidenceFilterOnly,
                                                   ActionListener listener) {
        evidenceFilter.addActionListener(listener);
        evidenceFilterOnly.addActionListener(e -> evidenceFilterObjectiveOnly(evidenceFilterOnly));
    }

    /**
     * Create a JButton for actions within the extension
     *
     * @param icon        the icon for the button
     * @param toolTipText the text to display for help
     * @param listener    the action associated to the button
     * @return the JButton
     */
    private JButton createJButton(ImageIcon icon, String toolTipText, ActionListener listener) {
        final JButton button = new JButton();
        button.setMargin(new Insets(0, 0, 0, 0));
        button.setMaximumSize(new Dimension(36, 36));
        button.setMinimumSize(new Dimension(36, 36));
        button.setPreferredSize(new Dimension(36, 36));
        button.setIcon(icon);
        button.setToolTipText(toolTipText);
        BurpExtender.callbacks.customizeUiComponent(button);
        button.addActionListener(listener);
        return button;
    }

    // httpRequestResponses filter default
    private void evidenceFilterSetDefaults() {
        filterPopup.evidenceFilters.forEach(filter -> {
            filter.setSelected(true);
            filter.setEnabled(true);
        });
        filterPopup.evidenceFiltersOnly.forEach(filter -> filter.setSelected(false));
        filterPopup.evidenceFiltersOnlyOrigin.forEach(filter -> filter = true);
        filterPopup.evidenceFilterBottom.requestFocus();
        evidenceFilterUpdate();
    }

    private void evidenceFilterSelectAll() {
        evidenceFilterSetDefaults();
    }

    private void evidenceFilterDeselectAll() {
        evidenceFilterSetDefaults();
        filterPopup.evidenceFilters.forEach(filter -> filter.setSelected(false));
    }

    @Override
    public String getTabCaption() {
        return "Evidence Collector";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // httpRequestResponses filter update
    private void evidenceFilterUpdate() {
        final ArrayList<RowFilter<EvidencerTableModel, Number>> mergedFilter = new ArrayList<>();
        RowFilter<EvidencerTableModel, Number> manualFilter = new RowFilter<>() {
            @Override
            public boolean include(Entry<? extends EvidencerTableModel, ? extends Number> entry) {
                HttpRequestResponse requestResponse;
                requestResponse = httpRequestResponses.get(entry.getIdentifier().intValue());
                boolean result = true;
                if (!objectiveFilterProcessing(requestResponse.objective)) {
                    result = false;
                }
                return result;
            }
        };
        mergedFilter.add(manualFilter);
        if (evidencerWorker != null) {
            try {
                evidencerWorker.cancel(true);
            } catch (Exception ex) {
                BurpExtender.stderr.println(ex.getMessage());
            }
        }
        (evidencerWorker = new EvidencerWorker(this, RowFilter.andFilter(mergedFilter))).execute();
    }

    private boolean objectiveFilterProcessing(String objective) {
        boolean process = true;
        switch (objective) {
            case Utils.A1:
                if (!filterPopup.evidenceFilterA1.isSelected()) process = false;
                break;
            case Utils.A2:
                if (!filterPopup.evidenceFilterA2.isSelected()) process = false;
                break;
            case Utils.A3:
                if (!filterPopup.evidenceFilterA3.isSelected()) process = false;
                break;
            case Utils.A4:
                if (!filterPopup.evidenceFilterA4.isSelected()) process = false;
                break;
            case Utils.A5:
                if (!filterPopup.evidenceFilterA5.isSelected()) process = false;
                break;
            case Utils.A6:
                if (!filterPopup.evidenceFilterA6.isSelected()) process = false;
                break;
            case Utils.A7:
                if (!filterPopup.evidenceFilterA7.isSelected()) process = false;
                break;
            case Utils.A8:
                if (!filterPopup.evidenceFilterA8.isSelected()) process = false;
                break;
            case Utils.A9:
                if (!filterPopup.evidenceFilterA9.isSelected()) process = false;
                break;
            case Utils.A10:
                if (!filterPopup.evidenceFilterA10.isSelected()) process = false;
                break;
        }
        return process;
    }

    /**
     * Handles the check boxes for test objectives (i.e. which is ticked and which isn't depending on user
     * actions)
     *
     * @param which the ticked checkBox
     */
    private void evidenceFilterObjectiveOnly(JCheckBox which) {
        for (int i = 0; i < filterPopup.evidenceFilters.size(); i++) {
            JCheckBox boxOnly = filterPopup.evidenceFiltersOnly.get(i);
            if (which != boxOnly && boxOnly.isSelected()) {
                boxOnly.setSelected(false);
                filterPopup.evidenceFilters.get(i).setSelected(filterPopup.evidenceFiltersOnlyOrigin.get(i));
            }
            if (which == boxOnly && !boxOnly.isSelected()) {
                filterPopup.evidenceFilters.get(i).setSelected(filterPopup.evidenceFiltersOnlyOrigin.get(i));
            }
        }

        if (which.isSelected()) {
            for (int i = 0; i < filterPopup.evidenceFilters.size(); i++) {
                filterPopup.evidenceFilters.get(i).setEnabled(false);
                filterPopup.evidenceFilters.get(i).setSelected(which == filterPopup.evidenceFiltersOnly.get(i));
            }
        } else {
            for (int i = 0; i < filterPopup.evidenceFilters.size(); i++) {
                filterPopup.evidenceFilters.get(i).setSelected(filterPopup.evidenceFiltersOnlyOrigin.get(i));
                filterPopup.evidenceFilters.get(i).setEnabled(true);
            }
        }
        evidenceFilterUpdate();
    }

}
